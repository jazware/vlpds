// The Spaces scenario matrix (README.md). Each configuration places the roles
// (authority/space host, two writers, a read-only member, an outsider; the
// syncer reads with the read-only member's delegation) on ref-a, ref-b or
// vlpds, then runs the same steps. Each step ends pass / fail / not impl.
// (a method answered 501) / blocked / skip, so the table doubles as a
// progress tracker. ref-ref runs first: it validates the harness itself.
//
//   node e2e.mjs [config ...]     configs: ref-ref vlpds-authority ref-authority vlpds-only
//   (VLPDS_BIN=... starts vlpds; CLUSTER=1 for 3 nodes; see run.sh)
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto'
import {
  COMMIT_MAC_TYPE,
  LtHash,
  RECORD_MAC_TYPE,
  RepoCommit,
  WANT_MAC_HEADER,
  createSpaceSigHeaders,
  encapsulate,
  formatWantMacHeader,
  parseMacHeader,
  verifyCommit,
  verifyRecord,
  verifyRepoStarFull,
} from '@atproto/space'
import { APP_SCOPE, Actor, RUN } from './lib/actor.mjs'
import { COLL, COLL_ALT, HOSTS, PORTS, REF_ADMIN_PASSWORD, SPACE_TYPE, VLPDS_ADMIN_TOKEN, log } from './lib/env.mjs'
import { NotImplemented, attempt, rawXrpc, sleep, setTimingScope, waitFor } from './lib/http.mjs'
import { kemKey, pdsEndpoint } from './lib/identity.mjs'
import { FirehoseTap, SENTINEL, checkAuthor } from './lib/leak.mjs'
import { NotifyService } from './lib/notifysvc.mjs'
import { Report, summarize } from './lib/report.mjs'
import {
  POLICY,
  SpaceCred,
  createSpace,
  credentialFor,
  decodeJwt,
  delegationToken,
  exchange,
  headOf,
  putMember,
  repoHost,
  spaceUri,
} from './lib/space.mjs'
import { Syncer, hashEq } from './lib/syncer.mjs'
import { Vlpds } from './lib/vlpds.mjs'

export const CONFIGS = {
  'ref-ref': { A: 'ref-a', W1: 'ref-a', W2: 'ref-b', R: 'ref-b', X: 'ref-a' },
  'vlpds-authority': { A: 'vlpds', W1: 'vlpds', W2: 'ref-a', R: 'ref-b', X: 'ref-b' },
  'ref-authority': { A: 'ref-a', W1: 'ref-b', W2: 'vlpds', R: 'vlpds', X: 'vlpds' },
  'vlpds-only': { A: 'vlpds', W1: 'vlpds', W2: 'vlpds', R: 'vlpds', X: 'vlpds' },
}

const usesVlpds = (cfg) => Object.values(CONFIGS[cfg]).includes('vlpds')
const record = (text, extra = {}) => ({ $type: COLL, text, createdAt: new Date().toISOString(), ...extra })
const errName = (r) => r.error ?? `HTTP ${r.status}`
const rkeyOf = (uri) => uri.split('/').pop()
// the digest clearRecords leaves (an empty repo's LtHash)
const EMPTY_DATA = 'e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad'

/** Ground truth of acked space writes: space -> did -> path -> cid. */
class Truth {
  m = new Map()
  repo(space, did) {
    if (!this.m.has(space)) this.m.set(space, new Map())
    const s = this.m.get(space)
    if (!s.has(did)) s.set(did, new Map())
    return s.get(did)
  }
  set(space, did, path, cid) {
    this.repo(space, did).set(path, String(cid))
  }
  del(space, did, path) {
    this.repo(space, did).delete(path)
  }
}

function mapDiff(want, got) {
  const out = []
  for (const [k, v] of want) if (got?.get(k) !== v) out.push(`${k}: want ${v} got ${got?.get(k)}`)
  for (const [k, v] of got ?? []) if (!want.has(k)) out.push(`${k}: unexpected ${v}`)
  return out
}

async function listAll(client, space, repo) {
  const out = new Map()
  let cursor
  do {
    const r = await client.com.atproto.space.listRecords({ space, repo, cursor, limit: 100 })
    for (const rec of r.data.records) out.set(`${rec.collection}/${rec.rkey}`, String(rec.cid))
    cursor = r.data.cursor
  } while (cursor)
  return out
}

function adminAuth(hostKey) {
  const pw = HOSTS[hostKey].kind === 'vlpds' ? VLPDS_ADMIN_TOKEN : REF_ADMIN_PASSWORD
  return `Basic ${Buffer.from(`admin:${pw}`).toString('base64')}`
}

/** The LtHash digest of a repo's path -> cid map. */
function ltOf(paths) {
  const h = new LtHash()
  for (const [p, cid] of paths) h.add(`${p}/${cid}`)
  return h.digest()
}

const hex = (b) => Buffer.from(b ?? []).toString('hex')
const bytesOf = (lexBytes) => Buffer.from(lexBytes?.$bytes ?? '', 'base64')

/** getRepo of `did` with a MAC: the STAR bytes and the verified archive (null when it doesn't verify). */
async function repoOf(cred, space, did) {
  const { res, sharedSecret, mac } = await cred.macRead(did, COMMIT_MAC_TYPE, (cl, opts) => cl.com.atproto.space.getRepo({ space, repo: did }, opts))
  const bytes = Buffer.from(res.data)
  const verified = mac ? await verifyRepoStarFull([bytes], { space, repo: did, sharedSecret, mac }) : null
  return { bytes, verified, res }
}

/** rawXrpc as a vlpds OAuth account (DPoP), for methods the typed client has no lexicon for. */
async function dpopXrpc(actor, nsid, opts = {}) {
  const signer = actor.oauth.signer()
  let r
  for (let i = 0; i < 2; i++) {
    const headers = new Headers()
    await signer({ method: opts.method ?? 'GET', url: `${actor.base}/xrpc/${nsid}`, headers })
    r = await rawXrpc(actor.base, nsid, { ...opts, headers: Object.fromEntries(headers) })
    if (!(await signer.retry(r))) break
  }
  return r
}

/** A compact r||s P-256 signature as DER, and as its high-S twin. */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const big = (b) => BigInt(`0x${Buffer.from(b).toString('hex') || '0'}`)
const be32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex')
function derOf(sig) {
  const int = (b) => {
    let x = Buffer.from(b)
    while (x.length > 1 && x[0] === 0 && !(x[1] & 0x80)) x = x.subarray(1)
    if (x[0] & 0x80) x = Buffer.concat([Buffer.from([0]), x])
    return Buffer.concat([Buffer.from([0x02, x.length]), x])
  }
  const body = Buffer.concat([int(sig.subarray(0, 32)), int(sig.subarray(32))])
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}
function highS(sig) {
  const s = big(sig.subarray(32))
  return Buffer.concat([Buffer.from(sig.subarray(0, 32)), be32(s > N / 2n ? s : N - s)])
}
const LABEL = 'atproto-space-credential'
function withSig(h, sigBytes, { pad = true } = {}) {
  const b64 = Buffer.from(sigBytes).toString('base64')
  return { ...h, signature: `${LABEL}=:${pad ? b64 : b64.replace(/=+$/, '')}:` }
}
function sigOf(h) {
  return Buffer.from(/=:([^:]+):/.exec(h.signature)[1], 'base64')
}

export async function runConfig(rep, cfg, env) {
  const P = CONFIGS[cfg]
  const truth = new Truth()
  const S = {} // shared state between steps
  const step = (name, fn, opts) => rep.step(cfg, name, fn, opts)
  const vl = (role) => HOSTS[P[role]].kind === 'vlpds'

  await step('setup.accounts', async (check) => {
    for (const role of ['A', 'W1', 'W2', 'R', 'X']) {
      try {
        S[role] = await Actor.create(P[role], role.toLowerCase())
      } catch (e) {
        if (P[role] === 'vlpds' && /scope|PAR|consent/i.test(e.message)) {
          // the space: scope may not parse yet; carry on without it so the
          // endpoints still get probed (and report 501 / scope errors)
          rep.note(`${cfg}: OAuth grant with the space: scope refused on vlpds (${e.message.slice(0, 200)}); retried without it`)
          const a = await Actor.create(P[role], role.toLowerCase(), { oauth: false })
          await a.authorize('atproto blob:*/* repo:*')
          a.scopeDegraded = true
          S[role] = a
        } else throw e
      }
      check(S[role].did?.startsWith('did:plc:'), `${role} on ${P[role]} has a did:plc`)
      if (S[role].oauth && !S[role].oauth.scope?.includes('space:') && !S.scopeNoted) {
        S.scopeNoted = true
        rep.note(`${cfg}: vlpds granted "${S[role].oauth.scope}" for a request of "${APP_SCOPE}" (the space: permission was dropped)`)
      }
    }
    for (const role of ['W1', 'W2']) {
      const k = await attempt(() => kemKey(S[role].did).then((data) => ({ data })))
      check(k.ok && /^did:key:zDn/.test(k.data), `${role}'s DID document publishes a P-256 #atproto_kem key`, k.ok ? k.data : k.error ?? '')
    }
    S.skey = `${SENTINEL}${cfg.replace(/[^a-z]/g, '')}`
    S.space = spaceUri(S.A.did, S.skey)
    S.taps = []
    for (const h of new Set(Object.values(P))) {
      for (const url of h === 'vlpds' && env.vlpds ? env.vlpds.urls() : [HOSTS[h].url]) {
        const tap = new FirehoseTap(url, `${h} ${url}`)
        await tap.open().catch((e) => rep.note(`${cfg}: firehose tap ${url}: ${e.message}`))
        S.taps.push(tap)
      }
    }
  })

  await step(
    'space.create',
    async (check) => {
      const uri = await createSpace(S.A, S.skey)
      check(uri === S.space, 'createSpace answers the space URI anchored on the caller', uri)
      const got = await S.A.client.com.atproto.space.getSpace({ space: S.space })
      const pol = got.data.policy ?? {}
      check(got.data.uri === S.space && pol.$type === 'com.atproto.memberspace.policy', 'getSpace answers the memberspace policy', JSON.stringify(got.data))
      check(
        pol.publicRead === false && pol.publicWrite === false && pol.publishPolicy === false && pol.publishMembers === false && pol.allowedApps === undefined,
        'with its defaults filled in (stored as enforced)',
        JSON.stringify(pol),
      )
      const dup = await attempt(() => createSpace(S.A, S.skey).then((data) => ({ data })))
      check(!dup.ok && dup.error === 'SpaceAlreadyExists', 'a second createSpace answers SpaceAlreadyExists', errName(dup))
      const unsupported = await attempt(() => createSpace(S.A, `${S.skey}x`, { policy: { $type: 'com.example.policy' } }).then((data) => ({ data })))
      check(!unsupported.ok && unsupported.error === 'UnsupportedPolicy', 'an unknown policy $type answers UnsupportedPolicy', errName(unsupported))
    },
    { needs: ['setup.accounts'] },
  )

  await step(
    'members',
    async (check) => {
      await putMember(S.A, S.space, S.W1, true, true)
      await putMember(S.A, S.space, S.W2, true, true)
      await putMember(S.A, S.space, S.R, true, false)
      const r = await S.A.client.com.atproto.memberspace.listMembers({ space: S.space })
      const got = Object.fromEntries(r.data.members.map((m) => [m.did, `${m.read}/${m.write}`]))
      check(got[S.W1.did] === 'true/true' && got[S.W2.did] === 'true/true', 'writers listed read+write', JSON.stringify(got))
      check(got[S.R.did] === 'true/false', 'reader listed read-only', JSON.stringify(got))
      check(!got[S.X.did], 'outsider not listed')
      const notOwner = await attempt(() => S.W1.client.com.atproto.memberspace.putMember({ space: S.space, did: S.X.did, read: true, write: true }))
      check(!notOwner.ok, 'a non-owner cannot putMember', errName(notOwner))
    },
    { needs: ['space.create'] },
  )

  await step(
    'records.write',
    async (check) => {
      const pub0 = {}
      for (const w of [S.W1, S.W2]) pub0[w.did] = (await rawXrpc(w.base, 'com.atproto.sync.getLatestCommit', { params: { did: w.did } })).json?.rev
      const c = S.W1.client.com.atproto.space
      const a = await c.createRecord({ space: S.space, repo: S.W1.did, collection: COLL, record: record(`hello ${SENTINEL}`) })
      const aPath = `${COLL}/${rkeyOf(a.data.uri)}`
      truth.set(S.space, S.W1.did, aPath, a.data.cid)
      check(a.data.uri.startsWith(`${S.space}/${S.W1.did}/${COLL}/`), 'the record URI is the 7-segment space form', a.data.uri)
      const srk = `${SENTINEL}-rk`
      const b = await c.createRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: srk, record: record('sentinel rkey') })
      truth.set(S.space, S.W1.did, `${COLL}/${srk}`, b.data.cid)
      S.srk = srk
      S.srkUri = b.data.uri
      const p1 = await c.putRecord({ space: S.space, repo: S.W1.did, collection: COLL_ALT, rkey: 'self', record: { ...record('v1'), $type: COLL_ALT } })
      const p2 = await c.putRecord({ space: S.space, repo: S.W1.did, collection: COLL_ALT, rkey: 'self', record: { ...record('v2'), $type: COLL_ALT } })
      check(String(p1.data.cid) !== String(p2.data.cid), 'putRecord replaces the value')
      truth.set(S.space, S.W1.did, `${COLL_ALT}/self`, p2.data.cid)
      const gone = await c.createRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: 'to-delete', record: record('bye') })
      check(!!gone.data.cid, 'created a record to delete')
      await c.deleteRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: 'to-delete' })
      const dup = await attempt(() => c.createRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: srk, record: record('again') }))
      check(!dup.ok && dup.error === 'RecordAlreadyExists', 'a duplicate create answers RecordAlreadyExists', errName(dup))
      const other = await attempt(() => c.createRecord({ space: S.space, repo: S.W2.did, collection: COLL, record: record('not mine') }))
      check(!other.ok, "writing into someone else's repo is refused", errName(other))
      // published policy and member records are the authority's PDS's to write
      for (const [collection, rkey] of [
        ['com.atproto.space.policy', 'self'],
        ['com.atproto.memberspace.member', S.W1.did],
      ]) {
        const direct = await attempt(() => c.putRecord({ space: S.space, repo: S.W1.did, collection, rkey, record: { $type: collection, read: true, write: true } }))
        check(!direct.ok && direct.status === 400, `a direct write to ${collection} is refused`, errName(direct))
      }

      const w2 = S.W2.client.com.atproto.space
      const aw = await w2.applyWrites({
        space: S.space,
        repo: S.W2.did,
        writes: [
          { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: 'aw1', value: record(`aw1 ${SENTINEL}`) },
          { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: 'aw2', value: record('aw2') },
          { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: 'aw3', value: record('aw3') },
        ],
      })
      check(aw.data.results?.length === 3, 'applyWrites answers one result per write')
      const aw2 = await w2.applyWrites({
        space: S.space,
        repo: S.W2.did,
        writes: [
          { $type: 'com.atproto.space.applyWrites#update', collection: COLL, rkey: 'aw2', value: record('aw2 v2') },
          { $type: 'com.atproto.space.applyWrites#delete', collection: COLL, rkey: 'aw3' },
        ],
      })
      truth.set(S.space, S.W2.did, `${COLL}/aw1`, aw.data.results[0].cid)
      truth.set(S.space, S.W2.did, `${COLL}/aw2`, aw2.data.results[0].cid)
      const atomic = await attempt(() =>
        w2.applyWrites({
          space: S.space,
          repo: S.W2.did,
          writes: [
            { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: 'aw4', value: record('aw4') },
            { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: 'aw1', value: record('dup') },
          ],
        }),
      )
      check(!atomic.ok, 'applyWrites with a duplicate create fails', errName(atomic))
      const aw4 = await attempt(() => w2.getRecord({ space: S.space, repo: S.W2.did, collection: COLL, rkey: 'aw4' }))
      check(!aw4.ok, 'and none of its writes applied (atomic)', errName(aw4))

      for (const w of [S.W1, S.W2]) {
        const own = await listAll(w.client, S.space, w.did)
        const d = mapDiff(truth.repo(S.space, w.did), own)
        check(!d.length, `${w}: listRecords of its own repo (read_self) equals what was acked`, d.join(', '))
        const pub1 = (await rawXrpc(w.base, 'com.atproto.sync.getLatestCommit', { params: { did: w.did } })).json?.rev
        check(pub1 === pub0[w.did], `${w}: space writes left the public repo's rev alone`, `${pub0[w.did]} -> ${pub1}`)
      }
      const g = await S.W1.client.com.atproto.space.getRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: srk })
      check(String(g.data.cid) === String(b.data.cid) && g.data.value?.text === 'sentinel rkey', 'getRecord (read_self) returns the value')
      // An OAuth caller's filters are the scope target (ref listSpaces.ts): a
      // grant for one space type lists only with spaceType set, and is refused
      // unfiltered or for another type. A password session (the ref) skips the check.
      const oauth = !!S.W1.oauth
      const ls = await S.W1.client.com.atproto.space.listSpaces(oauth ? { spaceType: SPACE_TYPE } : {})
      check(ls.data.spaces.some((s) => s.uri === S.space), 'listSpaces of a writer includes the space', JSON.stringify(ls.data.spaces.map((s) => s.uri)))
      const lsOther = await attempt(() => S.W1.client.com.atproto.space.listSpaces({ spaceType: 'com.example.otherType' }))
      if (oauth) {
        check(!lsOther.ok && lsOther.error === 'ScopeMissingError', 'listSpaces for a type the grant lacks is refused', errName(lsOther))
        const lsAll = await attempt(() => S.W1.client.com.atproto.space.listSpaces({}))
        check(!lsAll.ok && lsAll.error === 'ScopeMissingError', 'unfiltered listSpaces needs a wildcard grant', errName(lsAll))
      } else {
        check(lsOther.ok && !lsOther.data.spaces.some((s) => s.uri === S.space), 'listSpaces filters by spaceType', errName(lsOther))
      }
    },
    { needs: ['members'] },
  )

  await step(
    'records.self-only',
    async (check) => {
      const r = await attempt(() => S.W1.client.com.atproto.space.listRecords({ space: S.space, repo: S.W2.did }))
      check(!r.ok, "an OAuth/session read of another member's repo is refused (needs a credential)", errName(r))
      if (P.W1 === P.W2) check(r.error === 'RepoNotFound', 'with RepoNotFound (indistinguishable from absent)', errName(r))
      // a MAC is optional on a read of one's own data, and only answered when asked for
      const c = S.W1.client.com.atproto.space
      const plain = await c.getLatestCommit({ space: S.space, repo: S.W1.did })
      check(plain.headers['atproto-space-mac'] === undefined, "an own-data read that doesn't ask for a MAC gets none", plain.headers['atproto-space-mac'])
      const { keyShare, sharedSecret } = await encapsulate(await kemKey(S.W1.did))
      const asked = await c.getLatestCommit({ space: S.space, repo: S.W1.did }, { headers: { [WANT_MAC_HEADER]: formatWantMacHeader(COMMIT_MAC_TYPE, keyShare) } })
      const mac = asked.headers['atproto-space-mac'] ? parseMacHeader(asked.headers['atproto-space-mac'], COMMIT_MAC_TYPE) : null
      check(mac && verifyCommit(asked.data.commit, { space: S.space, repo: S.W1.did, sharedSecret, mac }), 'and one that asks gets a MAC that verifies')
    },
    { needs: ['records.write'] },
  )

  await step(
    'credential.issue',
    async (check) => {
      const tok = await delegationToken(S.R, S.space)
      const d = decodeJwt(tok)
      check(d.header.typ === 'atproto-space-delegation+jwt', 'delegation typ', d.header.typ)
      check(d.header.kid === '#atproto', 'delegation kid is exactly #atproto', d.header.kid)
      check(d.payload.iss === S.R.did && d.payload.sub === S.space, 'delegation iss=user sub=space', JSON.stringify(d.payload))
      check(d.payload.aud === `${S.A.did}#atproto_pds`, 'delegation aud = authority#atproto_pds', d.payload.aud)
      check(d.payload.exp - d.payload.iat <= 60, 'delegation lives at most 60 s', d.payload.exp - d.payload.iat)
      const key = await P256Keypair.create()
      const cred = await exchange(S.space, tok, { key })
      const c = cred.claims
      check(c.header.typ === 'atproto-space-credential+jwt', 'credential typ', c.header.typ)
      check(c.header.kid === '#atproto', 'credential kid is exactly #atproto', c.header.kid)
      check(c.payload.iss === S.A.did && c.payload.sub === S.space, 'credential iss=authority sub=space')
      check(c.payload.aud === undefined, 'credential carries no aud', c.payload.aud)
      check(c.payload.cnf?.kid === key.did(), 'credential cnf.kid is the credentialKid', JSON.stringify(c.payload.cnf))
      const life = c.payload.exp - c.payload.iat
      check(life > 0 && life <= 3600, 'credential lifetime within (0, 3600] s', life)
      check(life === 600, 'credential lifetime is the 600 s default', life)
      check(typeof c.payload.jti === 'string' && c.payload.jti.length > 0, 'credential has a jti')
      const again = await attempt(() => exchange(S.space, tok).then(() => ({ data: 1 })))
      check(!again.ok && again.error === 'InvalidDelegationToken', 'a delegation token is single-use (InvalidDelegationToken)', errName(again))
      const outsider = await attempt(() => credentialFor(S.X, S.space).then(() => ({ data: 1 })))
      check(!outsider.ok && outsider.error === 'SpaceNotFound', 'an outsider gets SpaceNotFound', errName(outsider))
      const tokenless = await attempt(() => exchange(S.space, undefined).then(() => ({ data: 1 })))
      check(!tokenless.ok && tokenless.error === 'SpaceNotFound', 'without a delegation token a members-only space answers SpaceNotFound', errName(tokenless))
      const k256 = await Secp256k1Keypair.create()
      const notP256 = await attempt(async () => exchange(S.space, await delegationToken(S.R, S.space), { credentialKid: k256.did() }).then(() => ({ data: 1 })))
      check(!notP256.ok && notP256.status === 400, 'a credentialKid that is not a P-256 did:key is refused', errName(notP256))
      const garbage = await attempt(() => exchange(S.space, `${tok.split('.').slice(0, 2).join('.')}.AAAA`).then(() => ({ data: 1 })))
      check(!garbage.ok && garbage.error === 'InvalidDelegationToken', 'a badly signed delegation token answers InvalidDelegationToken', errName(garbage))
      const otherSub = await attempt(async () => exchange(S.space, await delegationToken(S.R, `${S.space}x`)).then(() => ({ data: 1 })))
      check(!otherSub.ok && otherSub.error === 'InvalidDelegationToken', 'a delegation token for another space answers InvalidDelegationToken', errName(otherSub))
      S.cred = cred
    },
    { needs: ['members'] },
  )

  await step(
    'credential.read',
    async (check) => {
      for (const w of [S.W1, S.W2]) {
        const cl = await S.cred.repoClient(w.did)
        const got = await listAll(cl, S.space, w.did)
        const d = mapDiff(truth.repo(S.space, w.did), got)
        check(!d.length, `credential listRecords of ${w} equals the acked writes`, d.join(', '))
        const { res, sharedSecret, mac } = await S.cred.macRead(w.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.getLatestCommit({ space: S.space, repo: w.did }, opts))
        const commit = res.data.commit
        check(commit.ver === 1 && commit.repo === w.did && commit.space === S.space, `getLatestCommit of ${w} names its repo and space`, JSON.stringify({ ver: commit.ver, repo: commit.repo, space: commit.space }))
        check(mac && verifyCommit(commit, { space: S.space, repo: w.did, sharedSecret, mac }), `its MAC verifies with the secret encapsulated to ${w}'s #atproto_kem key`)
        check(mac && !verifyCommit(commit, { space: S.space, repo: w.did, sharedSecret: new Uint8Array(32), mac }), 'and not with another secret')
        check(/atproto-space-want-mac/i.test(res.headers.vary ?? ''), 'the response varies on Atproto-Space-Want-Mac', res.headers.vary)
        check(hashEq(commit.data, ltOf(truth.repo(S.space, w.did))), `its data equals the LtHash of the acked records (${w})`)
      }
      const host1 = await repoHost(S.W1.did)
      const cl1 = await S.cred.repoClient(S.W1.did)
      const noMac = await attempt(() => cl1.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W1.did }))
      check(!noMac.ok && noMac.error === 'BadSpaceMac', 'a credential read of getLatestCommit without Want-Mac answers BadSpaceMac', errName(noMac))
      const opsNoMac = await attempt(() => cl1.com.atproto.space.listRepoOps({ space: S.space, repo: S.W1.did }))
      check(!opsNoMac.ok && opsNoMac.error === 'BadSpaceMac', 'and listRepoOps', errName(opsNoMac))
      const badHeader = await attempt(() => cl1.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W1.did }, { headers: { [WANT_MAC_HEADER]: 'type="atproto-space-repo", ver=1, key_share="did:key:zQ3notakey"' } }))
      check(!badHeader.ok && badHeader.error === 'BadSpaceMac', 'a key_share that is not a P-256 did:key answers BadSpaceMac', errName(badHeader))
      const { keyShare } = await encapsulate(await kemKey(S.W1.did))
      const wrongType = await attempt(() => cl1.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W1.did }, { headers: { [WANT_MAC_HEADER]: formatWantMacHeader(RECORD_MAC_TYPE, keyShare) } }))
      check(!wrongType.ok && wrongType.error === 'BadSpaceMac', 'the record MAC type on getLatestCommit answers BadSpaceMac', errName(wrongType))
      const wrongVer = await attempt(() => cl1.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W1.did }, { headers: { [WANT_MAC_HEADER]: `type="atproto-space-repo", ver=2, key_share="${keyShare}"` } }))
      check(!wrongVer.ok && wrongVer.error === 'BadSpaceMac', 'an unsupported MAC version answers BadSpaceMac', errName(wrongVer))

      const uri = S.srkUri
      const rec = await S.cred.macRead(S.W1.did, RECORD_MAC_TYPE, (c, opts) => c.com.atproto.space.getRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: S.srk }, opts))
      check(rec.mac && (await verifyRecord({ uri: rec.res.data.uri, cid: String(rec.res.data.cid), value: rec.res.data.value }, { uri, sharedSecret: rec.sharedSecret, mac: rec.mac })), 'getRecord with a credential answers a record MAC that verifies (uri, cid, value)')
      const recNoMac = await attempt(() => cl1.com.atproto.space.getRecord({ space: S.space, repo: S.W1.did, collection: COLL, rkey: S.srk }))
      check(!recNoMac.ok && recNoMac.error === 'BadSpaceMac', 'and getRecord without Want-Mac answers BadSpaceMac', errName(recNoMac))

      const wrongAud = await attempt(() =>
        S.cred.client(host1, { audience: S.W2.did }).com.atproto.space.listRecords({ space: S.space, repo: S.W1.did }),
      )
      check(!wrongAud.ok && wrongAud.error === 'BadSpaceAudience', 'an audience other than the repo answers BadSpaceAudience', errName(wrongAud))
      const h0 = await S.cred.headersFor(S.W1.did)
      const raw = (headers) => rawXrpc(host1, 'com.atproto.space.listRecords', { params: { space: S.space, repo: S.W1.did }, headers })
      const der = await raw(withSig(h0, derOf(sigOf(h0))))
      check(!der.ok, 'a DER signature is refused', `${der.status} ${der.error}`)
      const hs = await raw(withSig(h0, highS(sigOf(h0))))
      check(hs.ok, 'a high-S signature is accepted', `${hs.status} ${hs.error} ${hs.message}`)
      const unpadded = await raw(withSig(h0, sigOf(h0), { pad: false }))
      check(unpadded.ok, 'an unpadded base64 signature is accepted', `${unpadded.status} ${unpadded.error} ${unpadded.message}`)
      const nosig = await raw({ authorization: h0.authorization, 'atproto-space-audience': S.W1.did })
      check(!nosig.ok, 'a credential without its HTTP signature is refused', `${nosig.status} ${nosig.error}`)
      const dupAud = await raw({ ...h0, 'atproto-space-audience': `${S.W1.did}, ${S.W2.did}` })
      check(!dupAud.ok, 'two Atproto-Space-Audience values are refused', `${dupAud.status} ${dupAud.error}`)
      const otherLabel = await raw({
        ...h0,
        'signature-input': `other=("authorization");keyid="did:key:zx", ${h0['signature-input']}`,
        signature: `other=:AAAA:, ${h0.signature}`,
      })
      check(otherLabel.ok, 'the atproto-space-credential label is found next to another signature label', `${otherLabel.status} ${otherLabel.error}`)
      const noTag = await raw({ ...h0, 'signature-input': h0['signature-input'].replace(/;tag="[^"]*"/, '') })
      check(!noTag.ok, 'a signature without tag="atproto-space-credential" is refused', `${noTag.status} ${noTag.error}`)
      const lower = await createSpaceSigHeaders(S.cred.key, { authorization: `atproto-space-credential ${S.cred.credential}`, audience: S.W1.did })
      const lc = await raw(lower)
      check(lc.ok, 'the scheme is recognized in lower case, signed over the value as sent', `${lc.status} ${lc.error} ${lc.message}`)
      const old = await createSpaceSigHeaders(S.cred.key, { authorization: `Atproto-Space ${S.cred.credential}`, audience: S.W1.did })
      const oldRes = await raw({ ...old, 'signature-input': old['signature-input'].replace(`${LABEL}=`, 'atproto-space='), signature: old.signature.replace(`${LABEL}=`, 'atproto-space=') })
      check(!oldRes.ok && oldRes.status === 400, 'the old Atproto-Space scheme is refused (400)', `${oldRes.status} ${oldRes.error}`)
      const cors = await rawXrpc(host1, 'com.atproto.space.getLatestCommit', {
        params: { space: S.space, repo: S.W1.did },
        headers: { ...h0, origin: 'https://app.example', [WANT_MAC_HEADER]: formatWantMacHeader(COMMIT_MAC_TYPE, (await encapsulate(await kemKey(S.W1.did))).keyShare) },
      })
      check(cors.ok && /atproto-space-mac/i.test(cors.headers.get('access-control-expose-headers') ?? ''), 'browsers may read Atproto-Space-Mac (Access-Control-Expose-Headers)', `${cors.status} ${cors.headers.get('access-control-expose-headers')}`)
      const tok = await delegationToken(S.R, S.space)
      const asCred = new SpaceCred(S.space, tok, S.cred.key)
      const conf = await attempt(() => asCred.client(host1).com.atproto.space.listRecords({ space: S.space, repo: S.W1.did }))
      check(!conf.ok, 'a delegation token is not accepted as a credential', errName(conf))
      const otherKey = new SpaceCred(S.space, S.cred.credential, await P256Keypair.create())
      const stolen = await attempt(() => otherKey.client(host1).com.atproto.space.listRecords({ space: S.space, repo: S.W1.did }))
      check(!stolen.ok, 'a credential signed with a key other than cnf.kid is refused', errName(stolen))
      const gs = await attempt(async () => (await S.cred.hostClient()).com.atproto.space.getSpace({ space: S.space }))
      check(!gs.ok, 'getSpace is owner-only: a space credential is refused', errName(gs))
    },
    { needs: ['credential.issue', 'records.write'] },
  )

  await step(
    'sync.full',
    async (check) => {
      S.syncer = new Syncer(`${cfg}-syncer`, S.space, S.R)
      await S.syncer.sync()
      if (S.syncer.lastError) throw S.syncer.lastError
      const dids = [...S.syncer.repos.keys()].sort()
      check(JSON.stringify(dids) === JSON.stringify([S.W1.did, S.W2.did].sort()), 'listRepos names exactly the two writers', JSON.stringify(dids))
      for (const w of [S.W1, S.W2]) {
        const d = mapDiff(truth.repo(S.space, w.did), S.syncer.view(w.did))
        check(!d.length, `syncer's copy of ${w} equals the acked writes`, d.join(', '))
      }
      check(!S.syncer.violations.length, 'no protocol violations', S.syncer.violations.join('; '))
      const { bytes, verified, res } = await repoOf(S.cred, S.space, S.W1.did)
      check(String(res.headers['content-type']).startsWith('application/octet-stream'), 'getRepo answers application/octet-stream', res.headers['content-type'])
      check(bytes[0] === 0x2a && bytes.at(-1) === 0x00, 'a STAR archive: the magic up front and the end byte last', `${bytes.subarray(0, 4).toString('hex')} .. ${bytes.subarray(-1).toString('hex')}`)
      check(verified?.records.length === truth.repo(S.space, S.W1.did).size, 'getRepo verifies (MAC + digest) and holds every record', verified?.records.length)
      const paths = (verified?.records ?? []).map((r) => `${r.collection}/${r.rkey}`)
      check(paths.every((p, i) => i === 0 || Buffer.compare(Buffer.from(paths[i - 1]), Buffer.from(p)) < 0), 'its records are in strict path order')
      check(verified && hashEq(RepoCommit.fromRecords(verified.records).setHash.digest(), verified.commit.data), "and fold to the commit's data")
      const { sharedSecret, mac } = await S.cred.macRead(S.W1.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.getRepo({ space: S.space, repo: S.W1.did }, opts))
      const truncated = await verifyRepoStarFull([bytes.subarray(0, -1)], { space: S.space, repo: S.W1.did, sharedSecret, mac }).then(
        () => null,
        (e) => e,
      )
      check(truncated, 'an archive cut before its end byte is rejected', 'accepted')
      const noMac = await attempt(async () => (await S.cred.repoClient(S.W1.did)).com.atproto.space.getRepo({ space: S.space, repo: S.W1.did }))
      check(!noMac.ok && noMac.error === 'BadSpaceMac', 'getRepo with a credential and no Want-Mac answers BadSpaceMac', errName(noMac))
      const ops = await S.cred.macRead(S.W1.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.listRepoOps({ space: S.space, repo: S.W1.did }, opts))
      check(!!ops.res.data.commit, 'a short listRepoOps page carries the commit')
      check(ops.mac && verifyCommit(ops.res.data.commit, { space: S.space, repo: S.W1.did, sharedSecret: ops.sharedSecret, mac: ops.mac }), 'with a MAC that verifies')
      // values are inlined for ops whose record is still current (stale ones are omitted)
      const cur = truth.repo(S.space, S.W1.did)
      const live = ops.res.data.ops.filter((o) => o.cid && cur.get(`${o.collection}/${o.rkey}`) === String(o.cid))
      check(live.length > 0 && live.every((o) => o.value !== undefined), 'listRepoOps inlines current values by default', JSON.stringify(ops.res.data.ops.map((o) => [o.rkey, !!o.cid, o.value !== undefined])))
      const page = await S.cred.macRead(S.W1.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.listRepoOps({ space: S.space, repo: S.W1.did, limit: 1 }, opts))
      if (page.res.data.cursor && !page.res.data.commit) check(page.mac === null, 'a listRepoOps page without the commit carries no MAC', 'got one')
    },
    { needs: ['credential.read'] },
  )

  await step(
    'notify.register',
    async (check) => {
      S.svc = env.svc
      const host = await S.cred.hostClient()
      const r = await host.com.atproto.space.registerNotify({ space: S.space, service: S.svc.serviceRef })
      const ttl = Date.parse(r.data.expiresAt) - Date.now()
      check(ttl > 60_000, 'registerNotify answers a future expiresAt', r.data.expiresAt)
      const bad = await attempt(() => host.com.atproto.space.registerNotify({ space: S.space, service: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#nope' }))
      check(!bad.ok && bad.error === 'ServiceNotResolvable', 'an unresolvable service answers ServiceNotResolvable', errName(bad))
      S.unsub = S.svc.on((call) => {
        if (call.lxm === 'com.atproto.space.notifyWrite' && call.body.space === S.space) S.syncer.notify(call.body)
      })
    },
    { needs: ['sync.full'] },
  )

  await step(
    'notify.write',
    async (check) => {
      const before = S.svc.callsTo('com.atproto.space.notifyWrite', S.space).length
      const t = {}
      for (const w of [S.W2, S.W1]) {
        const r = await w.client.com.atproto.space.createRecord({ space: S.space, repo: w.did, collection: COLL, record: record(`n ${SENTINEL}`) })
        truth.set(S.space, w.did, `${COLL}/${rkeyOf(r.data.uri)}`, r.data.cid)
        t[w.did] = performance.now()
      }
      const lat = []
      for (const w of [S.W1, S.W2]) {
        const head = await headOf(S.cred, S.space, w.did)
        const call = await waitFor(
          `forwarded notifyWrite for ${w}`,
          () => S.svc.callsTo('com.atproto.space.notifyWrite', S.space).slice(before).find((c) => c.body.repo === w.did && c.body.repoRev === head.rev),
          { timeoutMs: 20_000 },
        ).catch((e) => (check(false, e.message), null))
        if (!call) continue
        lat.push(call.at - t[w.did])
        check(!call.authErr, `forwarded notify for ${w} carries valid service auth (iss=authority, aud=service)`, call.authErr)
        check(typeof call.body.spaceRev === 'string', 'it carries a spaceRev')
        check(hashEq(bytesOf(call.body.data), head.data), 'its data is the repo digest', JSON.stringify(call.body).slice(0, 300))
        check(call.body.hash === undefined, 'and no hash field', JSON.stringify(call.body.hash))
      }
      const all = S.svc.callsTo('com.atproto.space.notifyWrite', S.space)
      for (let i = 1; i < all.length; i++) {
        if (!(all[i].body.spaceRev > all[i - 1].body.spaceRev)) check(false, 'spaceRev strictly increases across forwards', `${all[i - 1].body.spaceRev} then ${all[i].body.spaceRev}`)
        if (all[i].body.prevSpaceRev !== all[i - 1].body.spaceRev) check(false, 'prevSpaceRev names the previous forward', `${all[i].body.prevSpaceRev} vs ${all[i - 1].body.spaceRev}`)
      }
      rep.metrics[`${cfg}.notify_ms`] = summarize(lat)
      const host = await S.cred.hostClient()
      const lr = await host.com.atproto.space.listRepos({ space: S.space })
      for (const w of [S.W1, S.W2]) {
        const head = await headOf(S.cred, S.space, w.did)
        const e = lr.data.repos.find((x) => x.did === w.did)
        check(e?.repoRev === head.rev, `listRepos has ${w} at its latest repoRev`, `${e?.repoRev} vs ${head.rev}`)
        check(e && hashEq(e.data, head.data), `with its data`, `${hex(e?.data)} vs ${hex(head.data)}`)
      }
      const revs = lr.data.repos.map((x) => x.spaceRev)
      check(revs.every((r, i) => i === 0 || r > revs[i - 1]), 'listRepos is in ascending spaceRev')
      check(lr.data.cursor === revs.at(-1), 'its cursor is the last spaceRev')
      const empty = await host.com.atproto.space.listRepos({ space: S.space, cursor: lr.data.cursor })
      check(empty.data.repos.length === 0 && empty.data.cursor === undefined, 'the page after the last is empty and has no cursor')
    },
    { needs: ['notify.register'] },
  )

  await step(
    'sync.incremental',
    async (check) => {
      await S.syncer.idle()
      await S.syncer.sync()
      if (S.syncer.lastError) throw S.syncer.lastError
      for (const w of [S.W1, S.W2]) {
        const d = mapDiff(truth.repo(S.space, w.did), S.syncer.view(w.did))
        check(!d.length, `syncer converged on ${w}`, d.join(', '))
      }
      check(S.syncer.stats.opsPulls > 0, 'it pulled with listRepoOps', JSON.stringify(S.syncer.stats))
      check(S.syncer.stats.mismatchFallbacks === 0, 'no LtHash mismatch fell back to getRepo', JSON.stringify(S.syncer.stats))
      check(S.syncer.stats.macRetries === 0, 'every MAC verified on the first try', JSON.stringify(S.syncer.stats))
      check(!S.syncer.violations.length, 'no protocol violations', S.syncer.violations.join('; '))
      const rev = S.syncer.repos.get(S.W1.did).rev
      const noop = await S.cred.macRead(S.W1.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.listRepoOps({ space: S.space, repo: S.W1.did, since: rev }, opts))
      check(noop.res.data.ops.length === 0 && noop.res.data.commit?.rev === rev, 'a no-op poll answers no ops and the current commit', JSON.stringify({ n: noop.res.data.ops.length, rev: noop.res.data.commit?.rev }))
    },
    { needs: ['notify.write'] },
  )

  await step(
    'reader.write-untracked',
    async (check) => {
      const before = S.svc.callsTo('com.atproto.space.notifyWrite', S.space).length
      const r = await attempt(() => S.R.client.com.atproto.space.createRecord({ space: S.space, repo: S.R.did, collection: COLL, record: record('reader') }))
      check(r.ok, 'a read-only member may write its own repo (write permission only governs tracking)', errName(r))
      await sleep(2500)
      const lr = await (await S.cred.hostClient()).com.atproto.space.listRepos({ space: S.space })
      check(!lr.data.repos.some((x) => x.did === S.R.did), 'listRepos does not track the read-only member')
      check(!S.svc.callsTo('com.atproto.space.notifyWrite', S.space).slice(before).some((c) => c.body.repo === S.R.did), 'no notify is forwarded for it')
    },
    { needs: ['notify.register'] },
  )

  await step(
    'blobs',
    async (check) => {
      const bytes = Buffer.from(`space blob ${SENTINEL} ${Date.now()}`)
      const up = await S.W1.client.com.atproto.repo.uploadBlob(bytes, { encoding: 'text/plain' })
      const blob = up.data.blob
      const cid = blob.ref.toString()
      const r = await S.W1.client.com.atproto.space.createRecord({ space: S.space, repo: S.W1.did, collection: COLL, record: record('with blob', { file: blob }) })
      truth.set(S.space, S.W1.did, `${COLL}/${rkeyOf(r.data.uri)}`, r.data.cid)
      const cl = await S.cred.repoClient(S.W1.did)
      const got = await cl.com.atproto.space.getBlob({ space: S.space, repo: S.W1.did, cid })
      check(Buffer.from(got.data).equals(bytes), 'space.getBlob with a credential returns the bytes (no MAC)')
      const lb = await cl.com.atproto.space.listBlobs({ space: S.space, repo: S.W1.did })
      check(lb.data.cids.includes(cid), 'space.listBlobs lists it')
      const sync = await rawXrpc(S.W1.base, 'com.atproto.sync.getBlob', { params: { did: S.W1.did, cid } })
      check(!sync.ok && sync.error === 'BlobNotFound', 'sync.getBlob of a space-only blob answers BlobNotFound', `${sync.status} ${sync.error}`)
      const slb = await rawXrpc(S.W1.base, 'com.atproto.sync.listBlobs', { params: { did: S.W1.did } })
      check(!(slb.json?.cids ?? []).includes(cid), 'sync.listBlobs does not list it')
      const lone = await S.W1.client.com.atproto.repo.uploadBlob(Buffer.from(`unreferenced ${SENTINEL} ${Math.random()}`), { encoding: 'text/plain' })
      const loneCid = lone.data.blob.ref.toString()
      const s1 = await attempt(() => cl.com.atproto.space.getBlob({ space: S.space, repo: S.W1.did, cid: loneCid }))
      check(!s1.ok && s1.error === 'BlobNotFound', 'space.getBlob of an unreferenced upload answers BlobNotFound', errName(s1))
      const s2 = await rawXrpc(S.W1.base, 'com.atproto.sync.getBlob', { params: { did: S.W1.did, cid: loneCid } })
      check(!s2.ok, 'sync.getBlob does not serve an unreferenced upload (reference rule)', `${s2.status} ${s2.error}`)
      const pubBytes = Buffer.from(`public blob ${Date.now()}`)
      const pub = await S.W1.client.com.atproto.repo.uploadBlob(pubBytes, { encoding: 'text/plain' })
      await S.W1.client.com.atproto.repo.createRecord({
        repo: S.W1.did,
        collection: 'com.example.publicThing',
        record: { $type: 'com.example.publicThing', file: pub.data.blob, createdAt: new Date().toISOString() },
      })
      const s3 = await rawXrpc(S.W1.base, 'com.atproto.sync.getBlob', { params: { did: S.W1.did, cid: pub.data.blob.ref.toString() } })
      check(s3.ok && Buffer.from(s3.bytes).equals(pubBytes), 'control: a publicly referenced blob is served by sync.getBlob', `${s3.status} ${s3.error}`)
      const other = await attempt(() => cl.com.atproto.space.getBlob({ space: S.space, repo: S.W1.did, cid: pub.data.blob.ref.toString() }))
      check(!other.ok, 'space.getBlob does not serve a blob the space does not reference', errName(other))
      S.spaceBlobs = [cid, loneCid]
    },
    { needs: ['credential.read'] },
  )

  await step(
    'credential.revoke',
    async (check) => {
      const cred = await credentialFor(S.R, S.space)
      const target = S.W2
      const sa = await S.A.client.com.atproto.server.getServiceAuth({ aud: target.did, lxm: 'com.atproto.space.notifyCredentialRevoked' })
      const send = (jwt, body = { space: S.space, credentials: [cred.jti] }) =>
        rawXrpc(target.base, 'com.atproto.space.notifyCredentialRevoked', { method: 'POST', body, headers: { authorization: `Bearer ${jwt}` } })
      const first = await send(sa.data.token)
      check(first.ok, "the authority's revocation is accepted by the repo host", `${first.status} ${first.error} ${first.message}`)
      const sa2 = await S.A.client.com.atproto.server.getServiceAuth({ aud: target.did, lxm: 'com.atproto.space.notifyCredentialRevoked' })
      const again = await send(sa2.data.token)
      check(again.ok, 'a repeated revocation is idempotent', `${again.status} ${again.error}`)
      const r = await attempt(async () => (await cred.repoClient(target.did)).com.atproto.space.listRecords({ space: S.space, repo: target.did }))
      check(!r.ok && r.error === 'CredentialRevoked', 'the revoked credential answers CredentialRevoked there', errName(r))
      if (P.W1 !== P.W2) {
        const elsewhere = await attempt(async () => (await cred.repoClient(S.W1.did)).com.atproto.space.listRecords({ space: S.space, repo: S.W1.did }))
        check(elsewhere.ok, 'a host that was not told still accepts it until expiry', errName(elsewhere))
      }
      const fresh = await credentialFor(S.R, S.space)
      const ok = await attempt(async () => (await fresh.repoClient(target.did)).com.atproto.space.listRecords({ space: S.space, repo: target.did }))
      check(ok.ok, 'a fresh credential still reads', errName(ok))
      const forged = await S.W1.client.com.atproto.server.getServiceAuth({ aud: target.did, lxm: 'com.atproto.space.notifyCredentialRevoked' })
      const bad = await send(forged.data.token, { space: S.space, credentials: [fresh.jti] })
      check(!bad.ok, 'a revocation not issued by the authority is refused', `${bad.status} ${bad.error}`)
      const empty = await send((await S.A.client.com.atproto.server.getServiceAuth({ aud: target.did, lxm: 'com.atproto.space.notifyCredentialRevoked' })).data.token, { space: S.space, credentials: [] })
      check(!empty.ok, 'an empty credentials list is refused (1-100 jtis)', `${empty.status} ${empty.error}`)
    },
    { needs: ['credential.read'] },
  )

  await step(
    'notify.direct',
    async (check) => {
      const host = await pdsEndpoint(S.A.did)
      const sa = async (aud = `${S.A.did}#atproto_pds`, who = S.W1) =>
        (await who.client.com.atproto.server.getServiceAuth({ aud, lxm: 'com.atproto.space.notifyWrite' })).data.token
      const head = await headOf(S.cred, S.space, S.W1.did)
      const data = { $bytes: Buffer.from(head.data).toString('base64') }
      const send = async (body, token) => rawXrpc(host, 'com.atproto.space.notifyWrite', { method: 'POST', body: { space: S.space, repo: S.W1.did, data, ...body }, headers: token ? { authorization: `Bearer ${token}` } : {} })
      const future = tidAt(Date.now() + 10 * 60_000)
      const f = await send({ repoRev: future }, await sa())
      check(!f.ok && f.error === 'FutureRev', 'a repoRev 10 min ahead answers FutureRev', `${f.status} ${f.error}`)
      const lr0 = await (await S.cred.hostClient()).com.atproto.space.listRepos({ space: S.space })
      const s = await send({ repoRev: tidAt(Date.now() - 3600_000) }, await sa())
      check(s.ok, 'a stale repoRev is accepted', `${s.status} ${s.error}`)
      const lr1 = await (await S.cred.hostClient()).com.atproto.space.listRepos({ space: S.space })
      check(JSON.stringify(lr0.data.repos) === JSON.stringify(lr1.data.repos), 'and ignored: listRepos is unchanged (no resequencing)')
      const noAuth = await send({ repoRev: head.rev })
      check(!noAuth.ok, 'notifyWrite without service auth is refused', `${noAuth.status}`)
      const oldAud = await send({ repoRev: tidAt(Date.now() - 3600_000) }, await sa(`${S.A.did}#atproto_space_host`))
      check(!oldAud.ok, 'service auth for the old #atproto_space_host audience is refused', `${oldAud.status} ${oldAud.error}`)
      const bare = await send({ repoRev: tidAt(Date.now() - 3600_000) }, await sa(S.A.did))
      rep.note(`${cfg}: notifyWrite with the bare authority DID as aud: ${bare.ok ? 'accepted (as the reference does)' : `refused (${bare.status} ${bare.error})`}`)
      const xn = await rawXrpc(host, 'com.atproto.space.notifyWrite', {
        method: 'POST',
        body: { space: S.space, repo: S.X.did, repoRev: tidAt(Date.now()), data },
        headers: { authorization: `Bearer ${await sa(undefined, S.X)}` },
      })
      check(!xn.ok, 'a notify from a non-member writer is refused', `${xn.status} ${xn.error}`)
    },
    { needs: ['notify.write'] },
  )

  await step(
    'takedown',
    async (check) => {
      const set = (t, applied) =>
        rawXrpc(t.base, 'com.atproto.admin.updateSubjectStatus', {
          method: 'POST',
          headers: { authorization: adminAuth(t.host) },
          body: { subject: { $type: 'com.atproto.admin.defs#repoRef', did: t.did }, takedown: { applied, ref: applied ? 'spaces-e2e' : undefined } },
        })
      const reauth = async (t) => {
        if (HOSTS[t.host].kind !== 'vlpds' || !t.oauth) return
        // vlpds revokes an account's OAuth sessions at takedown and a reversal
        // doesn't bring them back (the reference keeps them): a recorded divergence
        const old = await attempt(() => t.client.com.atproto.space.getDelegationToken({ space: S.space }))
        check(!old.ok, `${t}: its OAuth session stays revoked after the reversal (divergence from the reference)`, errName(old))
        await t.authorize(APP_SCOPE)
        rep.note(`${cfg}: ${t} re-authorized after the takedown reversal (vlpds revokes OAuth sessions at takedown)`)
      }
      const t = S.W2
      const on = await set(t, true)
      check(on.ok, 'admin takedown of a writer', `${on.status} ${on.error} ${on.message}`)
      const cred = await credentialFor(S.R, S.space)
      const r = await attempt(async () => (await cred.repoClient(t.did)).com.atproto.space.listRecords({ space: S.space, repo: t.did }))
      check(!r.ok && r.error === 'RepoTakendown', 'credential reads of a taken-down repo answer RepoTakendown', errName(r))
      const off = await set(t, false)
      check(off.ok, 'reversal', `${off.status} ${off.error}`)
      const r2 = await attempt(async () => (await cred.repoClient(t.did)).com.atproto.space.listRecords({ space: S.space, repo: t.did }))
      check(r2.ok, 'reads work again after reversal', errName(r2))
      await reauth(t)

      // a taken-down authority suspends its spaces: no new credentials, no
      // listRepos, while credentials already issued keep reading members' repos
      const held = await credentialFor(S.R, S.space)
      const aon = await set(S.A, true)
      check(aon.ok, 'admin takedown of the authority', `${aon.status} ${aon.error} ${aon.message}`)
      try {
        const c = await attempt(async () => exchange(S.space, await delegationToken(S.R, S.space)).then(() => ({ data: 1 })))
        check(!c.ok && c.error === 'RepoTakendown', 'getSpaceCredential for a taken-down authority answers RepoTakendown', errName(c))
        const lr = await attempt(async () => (await held.hostClient()).com.atproto.space.listRepos({ space: S.space }))
        check(!lr.ok && lr.error === 'RepoTakendown', 'and listRepos', errName(lr))
        const still = await attempt(async () => (await held.repoClient(S.W1.did)).com.atproto.space.listRecords({ space: S.space, repo: S.W1.did }))
        check(still.ok, "a credential issued before keeps reading a member's repo (suspended, not deleted)", errName(still))
      } finally {
        const aoff = await set(S.A, false)
        check(aoff.ok, 'reversal', `${aoff.status} ${aoff.error}`)
      }
      const back = await attempt(() => credentialFor(S.R, S.space).then(() => ({ data: 1 })))
      check(back.ok, 'the space resumes: credentials issue again', errName(back))
      await reauth(S.A)
    },
    { needs: ['credential.read'] },
  )

  // vlpds's record takedown of a space record ("option e"): the record leaves
  // the authenticated view (getRepo verifies without it, the data is the
  // remaining records'), so a syncer converges on that view and back after
  // reversal. A vlpds that hides the record but keeps it in the digest (the
  // public-repo semantics) hasn't got option e yet: not impl., unless the
  // hiding it does already have regressed.
  await step(
    'takedown.record',
    async (check0) => {
      let clean = true
      const check = (ok, ...rest) => {
        if (!ok) clean = false
        return check0(ok, ...rest)
      }
      const w = S.W1
      const bytes = Buffer.from(`taken-down blob ${SENTINEL} ${Date.now()}`)
      const up = await w.client.com.atproto.repo.uploadBlob(bytes, { encoding: 'text/plain' })
      const blobCid = up.data.blob.ref.toString()
      S.spaceBlobs = [...(S.spaceBlobs ?? []), blobCid]
      const rkey = `td-${SENTINEL}`
      const made = await w.client.com.atproto.space.createRecord({ space: S.space, repo: w.did, collection: COLL, rkey, record: record(`taken down ${SENTINEL}`, { file: up.data.blob }) })
      const path = `${COLL}/${rkey}`
      truth.set(S.space, w.did, path, made.data.cid)
      const full = new Map(truth.repo(S.space, w.did))
      const without = new Map(full)
      without.delete(path)

      const syncer = new Syncer(`${cfg}-takedown`, S.space, S.R)
      await syncer.sync()
      if (syncer.lastError) throw syncer.lastError
      check(!mapDiff(full, syncer.view(w.did)).length, 'a fresh syncer starts from the full view', mapDiff(full, syncer.view(w.did)).join(', '))

      const set = (applied) =>
        rawXrpc(w.base, 'com.atproto.admin.updateSubjectStatus', {
          method: 'POST',
          headers: { authorization: adminAuth(w.host) },
          body: {
            subject: { $type: 'com.atproto.repo.strongRef', uri: made.data.uri, cid: String(made.data.cid) },
            takedown: { applied, ref: applied ? 'spaces-e2e-record' : undefined },
          },
        })
      const on = await set(true)
      if (!on.ok && /not supported|unsupported|not a space record/i.test(on.message ?? '')) {
        throw new NotImplemented('space record takedown', `(${on.status} ${on.error}: ${on.message})`)
      }
      check(on.ok, 'admin takedown of a space record (strongRef with the 7-segment URI)', `${on.status} ${on.error} ${on.message}`)
      if (!on.ok) return

      const takenDownView = async (check, cred, cl, head, blob) => {
        check(hashEq(head.data, ltOf(without)), "while taken down, getLatestCommit's data is the LtHash of the remaining records")
        check(!blob.ok && blob.error === 'BlobNotFound', "space.getBlob of the taken-down record's blob answers BlobNotFound", errName(blob))
        const lb = await cl.com.atproto.space.listBlobs({ space: S.space, repo: w.did })
        check(!lb.data.cids.includes(blobCid), 'space.listBlobs does not list it')
        const { verified } = await repoOf(cred, S.space, w.did)
        const got = new Map((verified?.records ?? []).map((r) => [`${r.collection}/${r.rkey}`, r.cid.toString()]))
        const d = mapDiff(without, got)
        check(verified && !d.length, 'getRepo verifies and holds every record but the taken-down one', verified ? d.join(', ') : 'did not verify')
        check(verified && hashEq(verified.commit.data, ltOf(without)), "getRepo's commit data is the remaining records' LtHash")
        let opsHead
        let cursor
        do {
          const page = await cred.macRead(w.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.listRepoOps({ space: S.space, repo: w.did, cursor, limit: 100 }, opts))
          opsHead = page.res.data.commit ?? opsHead
          cursor = page.res.data.cursor
        } while (cursor && !opsHead)
        check(opsHead && hashEq(opsHead.data, head.data), "listRepoOps's commit agrees with getLatestCommit")
        const before = syncer.stats.fullPulls
        await syncer.pull(w.did)
        const sd = mapDiff(without, syncer.view(w.did))
        check(!sd.length, 'the syncer converges on the view without the record', sd.join(', '))
        check(hashEq(syncer.repos.get(w.did).hash.digest(), ltOf(without)), "and its running LtHash is that view's")
        if (syncer.stats.fullPulls === before) rep.note(`${cfg}: the syncer reached the takedown view without a getRepo fallback`)
      }

      let optionE = false
      try {
        const cred = await credentialFor(S.R, S.space)
        const cl = await cred.repoClient(w.did)
        const g = await attempt(() => cred.macRead(w.did, RECORD_MAC_TYPE, (c, opts) => c.com.atproto.space.getRecord({ space: S.space, repo: w.did, collection: COLL, rkey }, opts)).then((r) => r.res))
        check(!g.ok && g.error === 'RecordNotFound', 'getRecord of the taken-down record answers RecordNotFound', errName(g))
        const listed = await listAll(cl, S.space, w.did)
        check(!listed.has(path), 'listRecords omits it')
        const ops = await cred.macRead(w.did, COMMIT_MAC_TYPE, (c, opts) => c.com.atproto.space.listRepoOps({ space: S.space, repo: w.did }, opts))
        check(
          !ops.res.data.ops.some((o) => `${o.collection}/${o.rkey}` === path && o.value !== undefined),
          'listRepoOps carries no value for it',
        )
        const head = await headOf(cred, S.space, w.did)
        const blob = await attempt(() => cl.com.atproto.space.getBlob({ space: S.space, repo: w.did, cid: blobCid }))
        optionE = !hashEq(head.data, ltOf(full))
        if (optionE) await takenDownView(check, cred, cl, head, blob)
        else
          rep.note(
            `${cfg}: space record takedown keeps the record in the digest (public-repo semantics, option e not landed); space.getBlob of its blob ${blob.ok ? 'is still served' : `answers ${errName(blob)}`}`,
          )
      } finally {
        const off = await set(false)
        check(off.ok, 'reversal', `${off.status} ${off.error} ${off.message}`)
      }
      const cred = await credentialFor(S.R, S.space)
      const cl = await cred.repoClient(w.did)
      const g = await attempt(() => cred.macRead(w.did, RECORD_MAC_TYPE, (c, opts) => c.com.atproto.space.getRecord({ space: S.space, repo: w.did, collection: COLL, rkey }, opts)).then((r) => r.res))
      check(g.ok && String(g.data.cid) === String(made.data.cid), 'after reversal getRecord returns it again', errName(g))
      const listed = await listAll(cl, S.space, w.did)
      check(!mapDiff(full, listed).length, 'and listRecords is the full view', mapDiff(full, listed).join(', '))
      const head = await headOf(cred, S.space, w.did)
      check(hashEq(head.data, ltOf(full)), "getLatestCommit's data is the full view's again")
      if (!optionE) {
        // what vlpds hides today passed; the record-free view isn't there yet
        if (clean) throw new NotImplemented('space record takedown (option e)', '(the record stays in the digest)')
        return
      }
      await syncer.pull(w.did)
      const sd = mapDiff(full, syncer.view(w.did))
      check(!sd.length, 'the syncer converges on the full view again', sd.join(', '))
      check(!syncer.violations.length, 'no protocol violations', syncer.violations.join('; '))
      const blob = await attempt(() => cl.com.atproto.space.getBlob({ space: S.space, repo: w.did, cid: blobCid }))
      check(blob.ok && Buffer.from(blob.data).equals(bytes), 'space.getBlob serves its blob again')
    },
    { needs: ['credential.read'], skip: vl('W1') ? undefined : 'vlpds extension; W1 is not on vlpds' },
  )

  // Operators may read space records for ToS moderation: admin auth only,
  // and audited. Not impl. until vlpds has an admin read of space records.
  await step(
    'operator.read',
    async (check) => {
      const w = S.W1
      const rkey = S.srk
      const params = { space: S.space, repo: w.did, collection: COLL, rkey }
      const auditOf = async () => {
        const r = await rawXrpc(w.base, 'vlpds.admin.getAuditLog', { params: { did: w.did, limit: 100 }, headers: { authorization: adminAuth(w.host) } }).catch((e) => ({ ok: false, error: e.message }))
        return r.ok ? r.json.entries : null
      }
      const before = await auditOf()
      const r = await rawXrpc(w.base, 'vlpds.admin.getSpaceRecord', { params, headers: { authorization: adminAuth(w.host) } })
      check(r.ok, 'admin auth reads a space record with vlpds.admin.getSpaceRecord', `${r.status} ${r.error} ${r.message}`)
      if (r.ok) {
        const want = truth.repo(S.space, w.did).get(`${COLL}/${rkey}`)
        check(String(r.json.cid) === want && r.json.value?.text === 'sentinel rkey', 'it returns the current record', JSON.stringify(r.json).slice(0, 300))
      }
      const member = await dpopXrpc(w, 'vlpds.admin.getSpaceRecord', { params })
      check(!member.ok, "a member's OAuth token cannot use it (its own record, even)", `${member.status} ${member.error}`)
      const outsider = S.X.oauth
        ? await dpopXrpc(S.X, 'vlpds.admin.getSpaceRecord', { params })
        : await rawXrpc(w.base, 'vlpds.admin.getSpaceRecord', { params, headers: { authorization: `Bearer ${S.X.session.accessJwt}` } })
      check(!outsider.ok, 'an unrelated account cannot use it', `${outsider.status} ${outsider.error}`)
      const wrong = await rawXrpc(w.base, 'vlpds.admin.getSpaceRecord', { params, headers: { authorization: `Basic ${Buffer.from('admin:not-the-token').toString('base64')}` } })
      check(!wrong.ok, 'a wrong admin password cannot use it', `${wrong.status} ${wrong.error}`)
      const after = await auditOf()
      if (!before || !after) {
        rep.note(`${cfg}: vlpds.admin.getAuditLog unreadable; the operator read's audit entry is unchecked`)
        return
      }
      const seen = new Set(before.map((e) => e.id))
      const fresh = after.filter((e) => !seen.has(e.id))
      check(
        fresh.some((e) => JSON.stringify(e).includes(S.space) || JSON.stringify(e).includes(rkey)),
        'the read left an audit entry naming the space record',
        JSON.stringify(fresh).slice(0, 400),
      )
    },
    { needs: ['records.write'], skip: vl('A') && vl('W1') ? undefined : 'vlpds extension; the space or W1 is not on vlpds' },
  )

  await step(
    'app-password',
    async (check) => {
      for (const w of [S.W1, S.W2]) {
        const jwt = await w.createAppPassword()
        const c = w.bearer(jwt)
        const write = await attempt(() => c.com.atproto.space.createRecord({ space: S.space, repo: w.did, collection: COLL, record: record('via app password') }))
        const del = await attempt(() => c.com.atproto.space.getDelegationToken({ space: S.space }))
        if (write.ok) truth.set(S.space, w.did, `${COLL}/${rkeyOf(write.data.uri)}`, write.data.cid)
        if (HOSTS[w.host].kind === 'vlpds') {
          check(!write.ok, `${w}: an app password cannot write space records (OAuth-only)`, errName(write))
          check(!del.ok, `${w}: an app password cannot mint delegation tokens`, errName(del))
          // not settled whether "OAuth-only" also refuses the account password's own session; recorded, not judged
          const sess = await attempt(() => w.sessionClient.com.atproto.space.getDelegationToken({ space: S.space }))
          const sw = await attempt(() => w.sessionClient.com.atproto.space.createRecord({ space: S.space, repo: w.did, collection: COLL, record: record('via password session') }))
          if (sw.ok) truth.set(S.space, w.did, `${COLL}/${rkeyOf(sw.data.uri)}`, sw.data.cid)
          rep.note(`${cfg}: ${w} password session: space write ${sw.ok ? 'accepted' : `refused (${errName(sw)})`}, getDelegationToken ${sess.ok ? 'accepted' : `refused (${errName(sess)})`}`)
        } else {
          check(write.ok, `${w}: the reference lets an app password write (ACCESS_STANDARD)`, errName(write))
          check(!del.ok, `${w}: but not mint a delegation token (ACCESS_FULL)`, errName(del))
        }
      }
    },
    { needs: ['records.write'] },
  )

  await step(
    'members.remove',
    async (check) => {
      const fresh = await credentialFor(S.R, S.space)
      const lr0 = await (await fresh.hostClient()).com.atproto.space.listRepos({ space: S.space })
      check(lr0.data.repos.some((x) => x.did === S.W2.did), 'W2 is a tracked writer before removal')
      await S.A.client.com.atproto.memberspace.removeMember({ space: S.space, did: S.W2.did })
      const m = await S.A.client.com.atproto.memberspace.listMembers({ space: S.space })
      check(!m.data.members.some((x) => x.did === S.W2.did), 'removed from listMembers')
      const c = await attempt(() => credentialFor(S.W2, S.space).then(() => ({ data: 1 })))
      check(!c.ok && c.error === 'SpaceNotFound', 'a removed member gets no credential (SpaceNotFound)', errName(c))
      const lr1 = await (await fresh.hostClient()).com.atproto.space.listRepos({ space: S.space })
      check(!lr1.data.repos.some((x) => x.did === S.W2.did), 'removeMember also drops it from the writer set (listRepos)')
      const w = await S.W2.client.com.atproto.space.createRecord({ space: S.space, repo: S.W2.did, collection: COLL, record: record('after removal') })
      truth.set(S.space, S.W2.did, `${COLL}/${rkeyOf(w.data.uri)}`, w.data.cid)
      await sleep(2500)
      const lr2 = await (await fresh.hostClient()).com.atproto.space.listRepos({ space: S.space })
      check(!lr2.data.repos.some((x) => x.did === S.W2.did), 'and a write after removal does not track it again')
    },
    { needs: ['notify.write'] },
  )

  await step(
    'writers.clear',
    async (check) => {
      const w = S.W1
      const c = w.client.com.atproto.space
      await S.syncer.idle()
      const mf0 = S.syncer.stats.mismatchFallbacks
      const head0 = await headOf(S.cred, S.space, w.did)
      const cleared = await c.clearRecords({ space: S.space, repo: w.did })
      check(!!cleared, 'clearRecords succeeds')
      truth.repo(S.space, w.did).clear()
      const own = await listAll(w.client, S.space, w.did)
      check(own.size === 0, 'the repo is empty', [...own.keys()].join(', '))
      const head = await headOf(S.cred, S.space, w.did)
      check(head.rev > head0.rev, 'at a new rev', `${head0.rev} -> ${head.rev}`)
      check(hex(head.data) === EMPTY_DATA, "with the empty repo's digest", hex(head.data))
      const noop = await c.clearRecords({ space: S.space, repo: w.did })
      check(!!noop && (await headOf(S.cred, S.space, w.did)).rev === head.rev, 'clearing an empty repo is a no-op (no new rev)')
      const other = await attempt(() => c.clearRecords({ space: S.space, repo: S.W2.did }))
      check(!other.ok, "clearing someone else's repo is refused", errName(other))
      const listed = await waitFor('listRepos to see the clear', async () => {
        const lr = await (await S.cred.hostClient()).com.atproto.space.listRepos({ space: S.space })
        const e = lr.data.repos.find((x) => x.did === w.did)
        return e?.repoRev === head.rev && e
      }, { timeoutMs: 20_000 }).catch(() => null)
      check(listed && hex(listed.data) === EMPTY_DATA, 'the writer stays listed, at the cleared rev and the empty digest', listed ? hex(listed.data) : 'not seen')
      // the forwarded notify may have pulled it already
      await S.syncer.idle()
      await S.syncer.pull(w.did)
      check(S.syncer.view(w.did)?.size === 0, "the syncer's copy is emptied", [...(S.syncer.view(w.did) ?? new Map()).keys()].join(', '))
      check(S.syncer.stats.mismatchFallbacks > mf0, 'by resyncing from getRepo after the data mismatch', JSON.stringify(S.syncer.stats))
      const again = await c.createRecord({ space: S.space, repo: w.did, collection: COLL, rkey: S.srk, record: record('sentinel rkey') })
      truth.set(S.space, w.did, `${COLL}/${S.srk}`, again.data.cid)
      await S.syncer.pull(w.did)
      check(!mapDiff(truth.repo(S.space, w.did), S.syncer.view(w.did)).length, 'a write afterwards repopulates it')
    },
    { needs: ['sync.full'] },
  )

  await step(
    'writers.remove',
    async (check) => {
      const w = S.W1
      const lr = async () => (await (await S.cred.hostClient()).com.atproto.space.listRepos({ space: S.space })).data.repos
      const r = await S.A.client.com.atproto.space.removeWriter({ space: S.space, did: w.did })
      check(!!r, 'removeWriter succeeds for the owner')
      check(!(await lr()).some((x) => x.did === w.did), 'the writer is gone from listRepos')
      const again = await attempt(() => S.A.client.com.atproto.space.removeWriter({ space: S.space, did: w.did }))
      check(again.ok, 'removeWriter is idempotent', errName(again))
      const notOwner = await attempt(() => S.R.client.com.atproto.space.removeWriter({ space: S.space, did: w.did }))
      check(!notOwner.ok, 'a non-owner cannot removeWriter', errName(notOwner))
      const own = await listAll(w.client, S.space, w.did)
      check(!mapDiff(truth.repo(S.space, w.did), own).length, "its records stay on its repo host")
      const n = await w.client.com.atproto.space.createRecord({ space: S.space, repo: w.did, collection: COLL, record: record('tracked again') })
      truth.set(S.space, w.did, `${COLL}/${rkeyOf(n.data.uri)}`, n.data.cid)
      const back = await waitFor('the writer to be tracked again', async () => (await lr()).some((x) => x.did === w.did), { timeoutMs: 20_000 }).catch(() => false)
      check(back, 'a write the policy authorizes tracks it again')
    },
    { needs: ['notify.write'] },
  )

  await step(
    'policies',
    async (check) => {
      const pubSpace = await createSpace(S.A, `${S.skey}pub`, { policy: POLICY.public })
      const c = await attempt(() => credentialFor(S.X, pubSpace).then((x) => ({ data: x })))
      check(c.ok, 'publicRead issues credentials to anyone', errName(c))
      const anon = await attempt(() => exchange(pubSpace, undefined).then((x) => ({ data: x })))
      check(anon.ok, 'and without a delegation token', errName(anon))
      await S.A.client.com.atproto.space.updateSpace({ space: pubSpace, policy: POLICY.members() })
      const after = await S.A.client.com.atproto.space.getSpace({ space: pubSpace })
      check(after.data.policy?.publicRead === false, 'updateSpace replaces the policy wholesale (publicRead back to false)', JSON.stringify(after.data.policy))
      const closed = await attempt(() => credentialFor(S.X, pubSpace).then((x) => ({ data: x })))
      check(!closed.ok && closed.error === 'SpaceNotFound', 'and an outsider gets SpaceNotFound again', errName(closed))

      const appsSpace = await createSpace(S.A, `${S.skey}apps`, { policy: POLICY.members({ allowedApps: ['https://app.example/client-metadata.json'] }) })
      await putMember(S.A, appsSpace, S.R, true, false)
      const noAtt = await attempt(() => credentialFor(S.R, appsSpace).then((x) => ({ data: x })))
      check(!noAtt.ok, 'allowedApps: a member without a client attestation is refused', errName(noAtt))
      if (!noAtt.ok) rep.note(`${cfg}: allowedApps without an attestation answers ${errName(noAtt)}`)
      const outsider = await attempt(() => credentialFor(S.X, appsSpace).then((x) => ({ data: x })))
      check(!outsider.ok && outsider.error === 'SpaceNotFound', 'and a non-member gets SpaceNotFound (the user is checked before the app)', errName(outsider))

      env.svc.access = (space, user, access) => space === S.appSpace && user === S.R.did && access === 'read'
      S.appSpace = await createSpace(S.A, `${S.skey}app`, { policy: POLICY.managed(env.svc.serviceRef) })
      const ok = await attempt(() => credentialFor(S.R, S.appSpace).then((x) => ({ data: x })))
      check(ok.ok, 'managedspace asks the app (checkUserAccess) and issues when it says yes', errName(ok))
      const no = await attempt(() => credentialFor(S.X, S.appSpace).then((x) => ({ data: x })))
      check(!no.ok, 'and refuses when it says no', errName(no))
      const mine = await attempt(() => credentialFor(S.A, S.appSpace).then((x) => ({ data: x })))
      check(mine.ok, 'the authority itself is authorized without asking', errName(mine))
      const tokenless = await attempt(() => exchange(S.appSpace, undefined).then((x) => ({ data: x })))
      check(!tokenless.ok && tokenless.error === 'SpaceNotFound', 'managedspace never issues without a delegation token', errName(tokenless))
      const asked = env.svc.callsTo('com.atproto.managedspace.checkUserAccess', S.appSpace)
      check(asked.length >= 2 && asked.every((a) => !a.authErr), 'checkUserAccess came with service auth from the authority (lxm com.atproto.managedspace.checkUserAccess)', asked.map((a) => a.authErr).join(','))
      check(asked.every((a) => a.body.access === 'read'), 'as read checks', JSON.stringify(asked.map((a) => a.body.access)))
      const pm = await attempt(() => S.A.client.com.atproto.memberspace.putMember({ space: S.appSpace, did: S.X.did, read: true, write: true }))
      check(!pm.ok && pm.error === 'PolicyMismatch', 'member methods on a managedspace answer PolicyMismatch', errName(pm))

      const persSpace = await createSpace(S.A, `${S.skey}pers`, { policy: POLICY.members() })
      await putMember(S.A, persSpace, S.R, true, false)
      await S.A.client.com.atproto.space.updateSpace({ space: persSpace, policy: POLICY.personal })
      const pr = await attempt(() => credentialFor(S.R, persSpace).then((x) => ({ data: x })))
      check(!pr.ok && pr.error === 'SpaceNotFound', 'personalspace: a former member gets SpaceNotFound', errName(pr))
      const po = await attempt(() => credentialFor(S.A, persSpace).then((x) => ({ data: x })))
      check(po.ok, 'and the owner still gets a credential', errName(po))
      await S.A.client.com.atproto.space.updateSpace({ space: persSpace, policy: POLICY.members() })
      const ml = await S.A.client.com.atproto.memberspace.listMembers({ space: persSpace })
      check(ml.data.members.length === 0, 'migrating away from memberspace discarded the member list', JSON.stringify(ml.data.members))
    },
    { needs: ['members'] },
  )

  await step(
    'policy.publish',
    async (check) => {
      const sp = await createSpace(S.A, `${S.skey}publ`, { policy: POLICY.members({ publishPolicy: true, publishMembers: true }) })
      await putMember(S.A, sp, S.R, true, false)
      const memberKey = S.R.did.replace(/%3A/gi, ':')
      const want = (own) => [own.has('com.atproto.space.policy/self'), own.has(`com.atproto.memberspace.member/${memberKey}`)]
      const own = await waitFor('the published records', async () => {
        const o = await listAll(S.A.client, sp, S.A.did)
        return want(o).every(Boolean) && o
      }, { timeoutMs: 10_000 }).catch(() => listAll(S.A.client, sp, S.A.did))
      const [pol, mem] = want(own)
      check(pol, "publishPolicy writes com.atproto.space.policy/self into the authority's repo", [...own.keys()].join(', '))
      check(mem, 'publishMembers writes a com.atproto.memberspace.member record per member', [...own.keys()].join(', '))
      const rec = await attempt(() => S.A.client.com.atproto.space.getRecord({ space: sp, repo: S.A.did, collection: 'com.atproto.memberspace.member', rkey: memberKey }))
      check(rec.ok && rec.data.value?.read === true && rec.data.value?.write === false, 'with the member\'s read and write', rec.ok ? JSON.stringify(rec.data.value) : errName(rec))
      await S.A.client.com.atproto.space.updateSpace({ space: sp, policy: POLICY.members() })
      const after = await listAll(S.A.client, sp, S.A.did)
      check(!want(after).some(Boolean), 'clearing the flags withdraws them', [...after.keys()].join(', '))
    },
    { needs: ['members'] },
  )

  await step(
    'import',
    async (check) => {
      const w = S.W1
      const c = w.client.com.atproto.space
      const snap = Buffer.from((await c.getRepo({ space: S.space, repo: w.did })).data)
      const want = new Map(truth.repo(S.space, w.did))
      const head0 = (await c.getLatestCommit({ space: S.space, repo: w.did })).data.commit
      const imp = await attempt(() => c.importRepo(snap, { encoding: 'application/octet-stream' }))
      check(imp.ok, 'importRepo of its own getRepo archive succeeds', errName(imp))
      const after = await listAll(w.client, S.space, w.did)
      check(!mapDiff(want, after).length, 'and the repo is unchanged', mapDiff(want, after).join(', '))
      const head1 = (await c.getLatestCommit({ space: S.space, repo: w.did })).data.commit
      check(head1.rev > head0.rev && hashEq(head1.data, head0.data), 'at a new rev with the same data', `${head0.rev} -> ${head1.rev}`)
      const extra = await c.createRecord({ space: S.space, repo: w.did, collection: COLL, record: record('after the export') })
      const old = await attempt(() => c.importRepo(snap, { encoding: 'application/octet-stream' }))
      check(old.ok, 'an older archive is imported too (an import replaces the repo, so a failed step can be retried)', errName(old))
      const after2 = await listAll(w.client, S.space, w.did)
      check(!after2.has(`${COLL}/${rkeyOf(extra.data.uri)}`) && !mapDiff(want, after2).length, "and replaces what's there", mapDiff(want, after2).join(', '))
      const cut = await attempt(() => c.importRepo(snap.subarray(0, -1), { encoding: 'application/octet-stream' }))
      check(!cut.ok && cut.status === 400, 'an archive cut before its end byte is refused', errName(cut))
      const afterCut = await listAll(w.client, S.space, w.did)
      if (!check(!mapDiff(want, afterCut).length, 'and the refused import leaves the repo as it was', `${want.size} records before, ${afterCut.size} after`)) {
        // put it back, so the later steps test their own thing
        await c.importRepo(snap, { encoding: 'application/octet-stream' })
      }
      const notMine = await attempt(() => S.X.client.com.atproto.space.importRepo(snap, { encoding: 'application/octet-stream' }))
      check(!notMine.ok, "another account can't import an archive whose commit names someone else", errName(notMine))
    },
    { needs: ['records.write'] },
  )

  await step(
    'space.meta',
    async (check) => {
      const c = S.A.client.com.atproto.space
      const members0 = (await S.A.client.com.atproto.memberspace.listMembers({ space: S.space })).data.members
      const w1Before = await listAll(S.W1.client, S.space, S.W1.did)
      const ex = await c.exportSpaceMeta({ space: S.space })
      const bytes = Buffer.from(ex.data)
      check(bytes[0] === 0x2a && bytes.at(-1) === 0x00, 'exportSpaceMeta answers a STAR archive (magic, end byte)', `${bytes.length} bytes`)
      const imp = await attempt(() => c.importSpaceMeta(bytes, { encoding: 'application/octet-stream' }))
      check(imp.ok, 'importSpaceMeta of it on the same host succeeds', errName(imp))
      const members1 = (await S.A.client.com.atproto.memberspace.listMembers({ space: S.space })).data.members
      const norm = (ms) => JSON.stringify(ms.map((m) => `${m.did} ${m.read} ${m.write}`).sort())
      check(norm(members0) === norm(members1), 'and leaves the member list as it was', `${norm(members0)} vs ${norm(members1)}`)
      const w1After = await listAll(S.W1.client, S.space, S.W1.did)
      check(w1Before.size > 0 && !mapDiff(w1Before, w1After).length, "and a member's repo as it was", `${w1Before.size} records before, ${w1After.size} after`)
      const cut = await attempt(() => c.importSpaceMeta(bytes.subarray(0, -1), { encoding: 'application/octet-stream' }))
      check(!cut.ok && cut.status === 400, 'a truncated meta archive is refused', errName(cut))
      const notOwner = await attempt(() => S.W1.client.com.atproto.space.importSpaceMeta(bytes, { encoding: 'application/octet-stream' }))
      check(!notOwner.ok, "an account can't import another authority's space", errName(notOwner))
      const exOther = await attempt(() => S.W1.client.com.atproto.space.exportSpaceMeta({ space: S.space }))
      check(!exOther.ok, 'exportSpaceMeta is owner-only', errName(exOther))
    },
    { needs: ['members'] },
  )

  await step(
    'space.delete',
    async (check) => {
      const fresh = await credentialFor(S.R, S.space)
      const own0 = await listAll(S.W1.client, S.space, S.W1.did)
      await S.A.client.com.atproto.space.deleteSpace({ space: S.space })
      const c = await attempt(() => credentialFor(S.R, S.space).then(() => ({ data: 1 })))
      check(!c.ok && c.error === 'SpaceDeleted', 'getSpaceCredential answers SpaceDeleted', errName(c))
      const anon = await attempt(() => exchange(S.space, undefined).then(() => ({ data: 1 })))
      check(!anon.ok && anon.error === 'SpaceDeleted', 'with or without a delegation token', errName(anon))
      const lr = await attempt(async () => (await fresh.hostClient()).com.atproto.space.listRepos({ space: S.space }))
      check(!lr.ok && lr.error === 'SpaceNotFound', 'listRepos answers SpaceNotFound', errName(lr))
      const told = await waitFor('notifySpaceDeleted', () => env.svc.callsTo('com.atproto.space.notifySpaceDeleted', S.space).length > 0, { timeoutMs: 15_000 }).catch(() => false)
      check(told, 'the registered syncer got notifySpaceDeleted')
      const own = await attempt(() => listAll(S.W1.client, S.space, S.W1.did).then((data) => ({ data })))
      check(own.ok && own.data.size === own0.size && own0.size > 0, "members' own repos stay (the writer can still read its repo)", own.ok ? `${own0.size} records before, ${own.data.size} after` : errName(own))
    },
    { needs: ['notify.register'] },
  )

  await step(
    'leak',
    async (check) => {
      if (process.env.LEAK_SELFTEST) {
        // prove the checker has teeth: a public record with the sentinel must be caught
        await S.W1.client.com.atproto.repo.createRecord({
          repo: S.W1.did,
          collection: 'com.example.publicThing',
          record: { $type: 'com.example.publicThing', text: `deliberate ${SENTINEL}`, createdAt: new Date().toISOString() },
        })
      }
      await sleep(1000)
      const backfills = []
      for (const t of S.taps) {
        const b = new FirehoseTap(t.base, `${t.label} cursor 0`)
        await b.open(0)
        backfills.push(b)
      }
      for (const b of backfills) await b.drain()
      for (const t of [...S.taps, ...backfills]) {
        check(t.frames > 0 || t.errors.length === 0, `${t.label}: firehose readable`, t.errors.join(';'))
        check(!t.hits.length, `${t.label}: no sentinel on the firehose (${t.frames} frames)`, t.hits[0])
        t.close()
      }
      const seen = new Set()
      for (const role of ['A', 'W1', 'W2', 'R', 'X']) {
        const a = S[role]
        if (seen.has(a.did)) continue
        seen.add(a.did)
        const leaks = await checkAuthor(a.base, a.did, role === 'W1' ? (S.spaceBlobs ?? []) : [])
        check(!leaks.length, `${a}: public sync surfaces clean`, leaks.join('; '))
      }
    },
    { needs: ['setup.accounts'] },
  )
  S.unsub?.()
  for (const t of S.taps ?? []) t.close()
  return S
}

/** A TID for a given wall time (microseconds since the epoch, base32-sortable). */
export function tidAt(ms) {
  const S32 = '234567abcdefghijklmnopqrstuvwxyz'
  let n = BigInt(ms) * 1000n
  let out = ''
  for (let i = 0; i < 11; i++) {
    out = S32[Number(n & 31n)] + out
    n >>= 5n
  }
  return `${out}22`
}

async function main() {
  const want = process.argv.slice(2).filter((a) => !a.startsWith('-'))
  const configs = want.length ? want : Object.keys(CONFIGS).filter((c) => c === 'ref-ref' || process.env.VLPDS_BIN)
  const rep = new Report(process.env.REPORT ?? 'e2e', {
    run: RUN,
    vlpds: process.env.VLPDS_REV ?? '(none)',
    reference: 'bluesky-social/atproto 98ef3a6b (@atproto/* 0.0.0-spaces-alpha-20261105160032)',
    cluster: !!process.env.CLUSTER,
    configs,
  })
  const env = {}
  env.svc = await new NotifyService(PORTS.syncer).start()
  if (configs.some(usesVlpds)) env.vlpds = await new Vlpds({ cluster: !!process.env.CLUSTER, memory: !!process.env.MEMORY }).start()
  try {
    for (const cfg of configs) {
      if (!CONFIGS[cfg]) throw new Error(`unknown config ${cfg}`)
      setTimingScope(cfg)
      await runConfig(rep, cfg, env)
    }
  } finally {
    const path = rep.write()
    log(`report: ${path}`)
    await env.svc.stop()
    if (env.vlpds && process.env.KEEP !== '1') await env.vlpds.stop()
  }
  console.log(`\n${rep.markdown()}`)
  process.exit(rep.failed().length ? 1 : 0)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e)
    process.exit(2)
  })
}
