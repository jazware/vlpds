// boards: user stories on a Reddit-like private message board built on
// Spaces, run against the harness stack (README.md). Each story is a report
// step (pass / fail / not impl. / blocked / skip); a config places the people
// on hosts. Assertions go against the appview's API (what a user sees) and
// against direct space reads (what the hosts serve).
//
//   node boards/scenarios.mjs [config ...]   configs: all-vlpds vlpds-owner ref-owner all-ref
//   (VLPDS_BIN starts vlpds; CLUSTER=1 for 3 nodes; SEED, SCALE=small|r2|full)
import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { crc32, deflateSync } from 'node:zlib'
import { P256Keypair } from '@atproto/crypto'
import { RECORD_MAC_TYPE } from '@atproto/space'
import { Actor, RUN } from '../lib/actor.mjs'
import { HOSTS, PORTS, VLPDS_ADMIN_TOKEN, log } from '../lib/env.mjs'
import { NotImplemented, attempt, hfetch, rawXrpc, setTimingScope, sleep, waitFor } from '../lib/http.mjs'
import { DpopKey, asPost } from '../lib/oauth.mjs'
import { FirehoseTap, SENTINEL, checkAuthor } from '../lib/leak.mjs'
import { NotifyService } from '../lib/notifysvc.mjs'
import { Report, summarize } from '../lib/report.mjs'
import { SpaceCred, credentialFor, headOf } from '../lib/space.mjs'
import { Vlpds } from '../lib/vlpds.mjs'
import { SCOPES, revokeCredentials, tid, voteRkey } from '../../../../boards/src/client.mjs'
import { C, boardView, materialize, parseRecordUri, sortPosts, thread } from '../../../../boards/src/model.mjs'
import { BoardsClient, harnessAppview } from './harness.mjs'

export const CONFIGS = {
  'all-vlpds': { alice: 'vlpds', bob: 'vlpds', carol: 'vlpds', dave: 'vlpds', eve: 'vlpds', bot: 'vlpds', crowd: ['vlpds'] },
  'vlpds-owner': { alice: 'vlpds', bob: 'vlpds', carol: 'ref-b', dave: 'ref-a', eve: 'ref-a', bot: 'ref-b', crowd: ['vlpds', 'ref-a', 'ref-b'] },
  'ref-owner': { alice: 'ref-a', bob: 'vlpds', carol: 'ref-b', dave: 'vlpds', eve: 'vlpds', bot: 'vlpds', crowd: ['ref-a', 'ref-b', 'vlpds'] },
  // the reference alone: checks the stories and the boards app, not vlpds
  'all-ref': { alice: 'ref-a', bob: 'ref-b', carol: 'ref-a', dave: 'ref-b', eve: 'ref-a', bot: 'ref-b', crowd: ['ref-a', 'ref-b'] },
}
const usesVlpds = (cfg) => Object.values(CONFIGS[cfg]).flat().includes('vlpds')

const CLUSTER = !!process.env.CLUSTER
const SEED = Number(process.env.SEED ?? 7)
const SCALES = {
  small: { members: 6, posts: 30, comments: 120, votes: 300 },
  r2: { members: 10, posts: 80, comments: 300, votes: 800 }, // a real bucket bills every request
  full: { members: 20, posts: 200, comments: 1000, votes: 3000 },
}
const SCALE = SCALES[process.env.SCALE] ?? SCALES.full
const CONC = Number(process.env.BOARDS_CONC ?? 16)
const NOTIFY_PORT = PORTS.syncer + 1
const API_PORT = PORTS.boardsUi
const UNCERTAIN = Symbol('uncertain')

const errName = (r) => r.error ?? `HTTP ${r.status}`
const adminAuth = () => `Basic ${Buffer.from(`admin:${VLPDS_ADMIN_TOKEN}`).toString('base64')}`
const pathOf = (uri) => {
  const u = parseRecordUri(uri)
  return `${u.collection}/${u.rkey}`
}

function mulberry32(a) {
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** A 1x1 PNG carrying `text` in a tEXt chunk. */
export function png(text) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4)
    len.writeUInt32BE(data.length)
    const td = Buffer.concat([Buffer.from(type), data])
    const crc = Buffer.alloc(4)
    crc.writeUInt32BE(crc32(td))
    return Buffer.concat([len, td, crc])
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(1, 0)
  ihdr.writeUInt32BE(1, 4)
  ihdr[8] = 8
  ihdr[9] = 2
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('tEXt', Buffer.from(`Comment\0${text}`)),
    chunk('IDAT', deflateSync(Buffer.from([0, 0xd9, 0x55, 0x2c]))),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

/** Acked writes: board -> did -> path -> { cid, value } (or UNCERTAIN). */
class Truth {
  m = new Map()
  repo(board, did) {
    if (!this.m.has(board)) this.m.set(board, new Map())
    const b = this.m.get(board)
    if (!b.has(did)) b.set(did, new Map())
    return b.get(did)
  }
  write(board, did, path, cid, value) {
    if (cid) this.repo(board, did).set(path, { cid, value })
    else this.repo(board, did).delete(path)
  }
  /** The board as the tracked writers' acked records make it, less taken-down paths. */
  model(board, { tracked, hidden = new Set() }) {
    const repos = new Map()
    for (const [did, recs] of this.m.get(board) ?? []) {
      if (!tracked.has(did)) continue
      repos.set(did, new Map([...recs].filter(([p, r]) => r !== UNCERTAIN && !hidden.has(`${did}/${p}`))))
    }
    return materialize(board, repos)
  }
}

const normPost = (p) => ({
  uri: p.uri,
  cid: p.cid,
  author: p.author,
  title: p.title,
  body: p.body,
  flair: p.flair,
  image: p.image?.cid,
  pinned: !!p.pinned,
  score: p.score,
  ups: p.ups,
  downs: p.downs,
  comments: p.comments,
  editedAt: p.editedAt,
})
const normTree = (list) => list.map((n) => ({ uri: n.uri, cid: n.cid, deleted: !!n.deleted, score: n.score, replies: normTree(n.replies) }))
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

/** Differences between the appview's API and the model (empty when they agree). */
async function compareView(av, board, model, { threads = true, karma = [], sorts = ['new', 'top', 'hot'] } = {}) {
  const diffs = []
  const bv = await av.getBoard(board)
  const want = boardView(model)
  for (const k of ['name', 'owner', 'posts', 'comments', 'members']) if (bv[k] !== want[k]) diffs.push(`board.${k}: ${bv[k]} want ${want[k]}`)
  if (!same(bv.pinned, want.pinned)) diffs.push(`board.pinned ${JSON.stringify(bv.pinned)} want ${JSON.stringify(want.pinned)}`)
  for (const sort of sorts) {
    const got = (await av.getPosts(board, sort, 1000)).posts
    const exp = sortPosts(model, sort)
    if (!same(got.map((p) => p.uri), exp.map((p) => p.uri))) {
      diffs.push(`${sort} order differs (${got.length} vs ${exp.length} posts)`)
      if (sort !== 'new') continue
    }
    if (sort !== 'new') continue
    const byUri = new Map(got.map((p) => [p.uri, p]))
    for (const p of exp) {
      const g = byUri.get(p.uri)
      if (!g) continue
      const a = normPost(g)
      const b = normPost(p)
      if (!same(a, b)) diffs.push(`post ${p.uri.split('/').pop()}: ${JSON.stringify(a)} want ${JSON.stringify(b)}`)
    }
  }
  if (threads) {
    for (const p of model.posts.values()) {
      const t = await av.getPostThread(p.uri)
      const exp = thread(model, p.uri)
      if (!same(normTree(t.replies), normTree(exp.replies))) diffs.push(`thread ${p.uri.split('/').pop()}: ${JSON.stringify(normTree(t.replies)).slice(0, 200)} want ${JSON.stringify(normTree(exp.replies)).slice(0, 200)}`)
    }
  }
  for (const did of karma) {
    const k = await av.getKarma(board, did)
    const e = model.karma.get(did) ?? { post: 0, comment: 0, total: 0 }
    if (!same(k, e)) diffs.push(`karma ${did}: ${JSON.stringify(k)} want ${JSON.stringify(e)}`)
  }
  return diffs
}

async function converge(fn, timeoutMs = 20_000, intervalMs = 50) {
  const t0 = performance.now()
  let diffs
  for (;;) {
    diffs = await fn().catch((e) => [`${e.error ?? ''} ${e.message}`])
    if (!diffs.length || performance.now() - t0 > timeoutMs) break
    await sleep(intervalMs)
  }
  return { ms: Math.round(performance.now() - t0), diffs }
}

async function listOwn(actor, space) {
  const out = new Map()
  let cursor
  do {
    const r = await actor.client.com.atproto.space.listRecords({ space, repo: actor.did, cursor, limit: 100 })
    for (const x of r.data.records) out.set(`${x.collection}/${x.rkey}`, { cid: String(x.cid), value: x.value })
    cursor = r.data.cursor
  } while (cursor)
  return out
}

async function listReposAll(cred, space) {
  const out = new Map()
  let cursor
  const host = await cred.hostClient()
  for (;;) {
    const r = await host.com.atproto.space.listRepos({ space, cursor, limit: 100 })
    if (!r.data.repos.length) break
    for (const e of r.data.repos) out.set(e.did, e)
    cursor = r.data.cursor
  }
  return out
}

const publicRev = async (a) => (await rawXrpc(a.base, 'com.atproto.sync.getLatestCommit', { params: { did: a.did } })).json?.rev

async function storeMetrics(env) {
  const m = env.vlpds ? await env.vlpds.metrics() : new Map()
  let store = 0
  const by = {}
  for (const [k, v] of m) {
    if (!k.startsWith('vlpds_object_store_requests_total{')) continue
    store += v
    const key = `${/op="([^"]+)"/.exec(k)?.[1]}/${/component="([^"]+)"/.exec(k)?.[1]}`
    by[key] = (by[key] ?? 0) + v
  }
  return { store, by }
}

function vlpdsSupports(flag) {
  try {
    return execFileSync(process.env.VLPDS_BIN, ['--help'], { encoding: 'utf8' }).includes(flag)
  } catch {
    return false
  }
}

/** The consent page vlpds shows `actor` for `scope` (PAR, sign-in, then the consent HTML; nothing is approved). */
async function consentHtml(actor, scope) {
  const base = actor.base
  const key = new DpopKey()
  const redirect = 'http://127.0.0.1/cb'
  const clientId = `http://localhost?scope=${encodeURIComponent(scope)}&redirect_uri=${encodeURIComponent(redirect)}`
  const par = await asPost(base, key, '/oauth/par', {
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirect,
    scope,
    state: 'consent-probe',
    code_challenge: createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url'),
    code_challenge_method: 'S256',
    login_hint: actor.handle,
  })
  if (par.status !== 201) throw new Error(`PAR ${par.status} ${JSON.stringify(par.body)}`)
  const ru = par.body.request_uri
  let cookie
  const go = async (url, form) => {
    const res = await hfetch(url, form ? { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) }, body: new URLSearchParams(form) } : { headers: cookie ? { cookie } : {} })
    for (const sc of res.headers.getSetCookie?.() ?? []) if (sc.startsWith('vlpds-device=')) cookie = sc.split(';')[0]
    return res.text()
  }
  const csrf = (html) => /name="csrf" value="([^"]*)"/.exec(html)?.[1]?.replace(/&amp;/g, '&')
  let html = await go(`${base}/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(ru)}`)
  if (html.includes('name="password"')) html = await go(`${base}/oauth/authorize/sign-in`, { request_uri: ru, csrf: csrf(html), identifier: actor.handle, password: actor.password, action: 'sign-in' })
  if (!html.includes('Authorize access')) throw new Error(`no consent page: ${html.replace(/\s+/g, ' ').slice(0, 300)}`)
  return html
}

/**
 * With --lexicon-authority-override in the binary: a vlpds account publishes
 * the boards lexicons as com.atproto.lexicon.schema records, and vlpds
 * restarts with boards.example.com pointed at it. Null when the flag is missing.
 */
export async function setupLexicons(env) {
  if (!vlpdsSupports('--lexicon-authority-override')) return null
  const pub = await Actor.create('vlpds', 'lexicons', { oauth: false })
  const dir = new URL('../../../../boards/lexicons/dev/example/boards/', import.meta.url)
  for (const name of ['board', 'settings', 'post', 'comment', 'vote']) {
    const doc = JSON.parse(readFileSync(new URL(`${name}.json`, dir), 'utf8'))
    await pub.sessionClient.com.atproto.repo.putRecord({ repo: pub.did, collection: 'com.atproto.lexicon.schema', rkey: doc.id, record: { $type: 'com.atproto.lexicon.schema', ...doc } })
  }
  await env.vlpds.stop()
  for (const n of env.vlpds.nodes) n.opts.extra.push('--lexicon-authority-override', `boards.example.com=${pub.did}`)
  await env.vlpds.start()
  log(`lexicons published by ${pub.handle} (${pub.did}); vlpds restarted with --lexicon-authority-override boards.example.com=${pub.did}`)
  return { did: pub.did, handle: pub.handle }
}

export async function runConfig(rep, cfg, env) {
  const P = CONFIGS[cfg]
  const label = `${cfg}${CLUSTER ? ' (cluster)' : ''}`
  const step = (name, fn, opts) => rep.step(label, name, fn, opts)
  const truth = new Truth()
  const S = { taps: [], spaceBlobs: [], actors: [], hidden: new Set() }
  const onWrite = (board, did, path, cid, value) => truth.write(board, did, path, cid, value)
  const model = (board = S.board) => truth.model(board, { tracked: S.tracked, hidden: S.hidden })
  const people = ['alice', 'bob', 'carol', 'dave', 'eve']

  await step('0.setup', async (check) => {
    for (const h of new Set([...Object.values(P).flat()])) {
      for (const url of h === 'vlpds' && env.vlpds ? env.vlpds.urls() : [HOSTS[h].url]) {
        const tap = new FirehoseTap(url, `${h} ${url}`)
        await tap.open().catch((e) => rep.note(`${label}: firehose tap ${url}: ${e.message}`))
        S.taps.push(tap)
      }
    }
    const scopeOf = { alice: SCOPES.owner, eve: SCOPES.owner, bot: SCOPES.reader }
    for (const who of [...people, 'bot']) {
      S[who] = await Actor.create(P[who], who, { scope: scopeOf[who] ?? SCOPES.member })
      S.actors.push(S[who])
      check(S[who].did.startsWith('did:plc:'), `${who} on ${P[who]}`)
    }
    for (const who of people) S[`${who}C`] = new BoardsClient(S[who], { onWrite })
    S.svc = await new NotifyService(NOTIFY_PORT).start()
    S.appview = await harnessAppview({ port: API_PORT, account: S.bot, svc: S.svc, pollMs: 2000 }).start()
    S.av = Object.fromEntries(people.map((who) => [who, S[`${who}C`].appview(`http://127.0.0.1:${API_PORT}`, S.appview.did)]))
    S.revs0 = new Map()
    for (const a of S.actors) S.revs0.set(a.did, await publicRev(a))
  })

  // C6: a bare space: grant takes the type declaration's collections. vlpds
  // resolves declarations over DNS (_lexicon.boards.example.com); in dev mode
  // --lexicon-authority-override points that authority at a local account
  // holding the com.atproto.lexicon.schema records (setupLexicons, once a run).
  await step('0.bare-grant', async (check) => {
    if (!env.lexicons) throw new NotImplemented('--lexicon-authority-override', '(not in this vlpds binary; a bare grant needs a resolvable dev.example.boards.board declaration)')
    const a = await Actor.create('vlpds', 'bare', { oauth: false })
    const html = await consentHtml(a, SCOPES.bare)
    check(html.includes('Board spaces'), 'the consent screen names the type by its declaration ("Board spaces")', html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 300))
    check([C.post, C.comment, C.vote].every((c) => html.includes(c)), "and lists the declaration's collections as the write targets")
    await a.authorize(SCOPES.bare)
    const granted = a.oauth.scope ?? ''
    check([C.settings, C.post, C.comment, C.vote].every((c) => granted.includes(`collection=${c}`)), 'the token carries the collections', granted)
    const bc = new BoardsClient(a, { onWrite })
    const B = await S.aliceC.createBoard(`${SENTINEL}bare`, { name: 'bare' })
    await S.aliceC.addMember(B, a.did)
    const post = await attempt(() => bc.post(B, { title: `bare grant ${SENTINEL}` }).then((data) => ({ data })))
    check(post.ok, 'a member on the bare grant posts', errName(post))
    const other = await attempt(() => a.client.com.atproto.space.createRecord({ space: B, repo: a.did, collection: 'com.example.notDeclared', record: { $type: 'com.example.notDeclared', text: SENTINEL } }))
    check(!other.ok, "and can't write a collection the declaration doesn't list", errName(other))
    await S.aliceC.deleteBoard(B)
    S.actors.push(a)
  }, { needs: ['0.setup'], skip: Object.values(P).flat().includes('vlpds') ? undefined : 'no vlpds account here' })

  await step('1.create-board', async (check) => {
    S.board = await S.aliceC.createBoard(`${SENTINEL}rust`, { name: 'rustaceans', description: `crabs only ${SENTINEL}`, flairs: ['question', 'show-and-tell'] })
    check(S.board === `at://${S.alice.did}/space/${C.post.replace('.post', '.board')}/${SENTINEL}rust`, 'the board is a space anchored on alice', S.board)
    await S.aliceC.addMember(S.board, S.bob.did)
    await S.aliceC.addMember(S.board, S.carol.did)
    await S.aliceC.addMember(S.board, S.dave.did, { write: false })
    await S.aliceC.addMember(S.board, S.bot.did, { write: false })
    S.tracked = new Set([S.alice.did, S.bob.did, S.carol.did])
    const members = Object.fromEntries((await S.aliceC.listMembers(S.board)).map((m) => [m.did, `${m.read}/${m.write}`]))
    check(members[S.bob.did] === 'true/true' && members[S.carol.did] === 'true/true', 'bob and carol are writers', JSON.stringify(members))
    check(members[S.dave.did] === 'true/false' && members[S.bot.did] === 'true/false', 'dave and the appview are lurkers')
    check(!members[S.eve.did], 'eve is not a member')
    const idx = await S.av.alice.indexBoard(S.board)
    check(idx.board === S.board, 'the appview indexes the board')
    const bv = await S.av.alice.getBoard(S.board)
    check(bv.name === 'rustaceans' && bv.owner === S.alice.did && bv.posts === 0, 'getBoard shows the settings', JSON.stringify(bv))
    check(same(bv.flairs, ['question', 'show-and-tell']), 'with its flairs')
    const anon = await S.av.eve.call('dev.example.boards.getBoard', null, { params: { board: S.board }, cred: null })
    check(anon.status === 401 && anon.error === 'AuthRequired', 'the appview answers AuthRequired without a credential', errName(anon))
  }, { needs: ['0.setup'] })

  await step('2.post-comment-vote', async (check) => {
    const t0 = Date.parse('2026-10-05T12:00:00Z')
    const at = (h) => new Date(t0 + h * 3600_000).toISOString()
    S.img = png(`crab ${SENTINEL} ${Date.now()}`)
    const B = S.board
    S.P1 = (await S.bobC.post(B, { title: `my crab ${SENTINEL}`, body: 'look at him', image: { bytes: S.img, mimeType: 'image/png', alt: 'a crab' }, flair: 'show-and-tell', createdAt: at(0) })).uri
    S.P2 = (await S.bobC.post(B, { title: 'question about lifetimes', body: `why 'a ${SENTINEL}`, flair: 'question', createdAt: at(1) })).uri
    S.P3 = (await S.carolC.post(B, { title: 'buy my coin', body: SENTINEL, flair: 'spam', createdAt: at(2) })).uri
    S.c1 = (await S.carolC.comment(B, S.P1, `nice crab ${SENTINEL}`, { createdAt: at(3) })).uri
    S.r1 = (await S.aliceC.comment(B, S.P1, `agreed ${SENTINEL}`, { parent: S.c1, createdAt: at(4) })).uri
    await S.bobC.vote(B, S.P1, 'up')
    await S.aliceC.vote(B, S.P1, 'up')
    await S.carolC.vote(B, S.P1, 'up')
    await S.carolC.vote(B, S.P1, 'down')
    await S.bobC.vote(B, S.P3, 'down')
    await S.aliceC.vote(B, S.c1, 'up')
    await S.bobC.vote(B, S.c1, 'up')
    await S.aliceC.unvote(B, S.c1)
    await S.carolC.vote(B, S.r1, 'down')

    const av = S.av.bob
    const conv = await converge(() => compareView(av, B, model(), { karma: [S.alice.did, S.bob.did, S.carol.did] }))
    check(!conv.diffs.length, `the appview converges on the model (${conv.ms} ms)`, conv.diffs.slice(0, 4).join('; '))
    // the same numbers by hand, so a shared model bug can't hide
    const posts = Object.fromEntries((await av.getPosts(B, 'new')).posts.map((p) => [p.uri, p]))
    const p1 = posts[S.P1]
    check(p1?.score === 1 && p1.ups === 2 && p1.downs === 1 && p1.comments === 2, 'P1: 2 up, 1 down (carol changed hers), 2 comments', JSON.stringify(p1))
    check(posts[S.P2]?.score === 0 && posts[S.P2].flair === 'question', 'P2: no votes, flair question')
    check(posts[S.P3]?.score === -1 && posts[S.P3].flair === undefined, "P3: -1, and its flair isn't one of the board's", JSON.stringify(posts[S.P3]))
    const th = await av.getPostThread(S.P1)
    check(th.replies.length === 1 && th.replies[0].uri === S.c1 && th.replies[0].score === 1, 'P1 thread: c1 at 1 (alice unvoted)', JSON.stringify(normTree(th.replies)))
    check(th.replies[0]?.replies[0]?.uri === S.r1 && th.replies[0].replies[0].score === -1, 'r1 under c1 at -1 (depth 2)')
    const karma = async (a) => (await av.getKarma(B, a.did)).total
    check((await karma(S.bob)) === 1 && (await karma(S.carol)) === 0 && (await karma(S.alice)) === -1, 'karma: bob 1, carol 0, alice -1')
    check(same((await av.getPosts(B, 'new')).posts.map((p) => p.uri), [S.P3, S.P2, S.P1]), 'new: P3, P2, P1')
    check(same((await av.getPosts(B, 'top')).posts.map((p) => p.uri), [S.P1, S.P2, S.P3]), 'top: P1, P2, P3')
    check(same((await av.getPosts(B, 'hot')).posts.map((p) => p.uri), [S.P3, S.P2, S.P1]), 'hot before pinning: newest first at |score| <= 1')
    await S.aliceC.pin(B, S.P1)
    const pinned = await converge(async () => {
      const h = (await av.getPosts(B, 'hot')).posts.map((p) => p.uri)
      return same(h, [S.P1, S.P3, S.P2]) ? [] : [`hot ${h.map((u) => u.split('/').pop())}`]
    })
    check(!pinned.diffs.length, 'alice pins P1: hot is P1, P3, P2', pinned.diffs.join())

    const imgCid = p1?.image?.cid
    S.imgCid = imgCid
    S.spaceBlobs.push(imgCid)
    const daveCred = await S.daveC.credential(B)
    const blob = await (await daveCred.repoClient(S.bob.did)).com.atproto.space.getBlob({ space: B, repo: S.bob.did, cid: imgCid })
    check(Buffer.from(blob.data).equals(S.img), 'space.getBlob with a credential returns the image')
    const sync = await rawXrpc(S.bob.base, 'com.atproto.sync.getBlob', { params: { did: S.bob.did, cid: imgCid } })
    check(!sync.ok && sync.error === 'BlobNotFound', 'sync.getBlob answers BlobNotFound', `${sync.status} ${sync.error}`)
    const viaAv = await S.av.dave.getImage(B, S.bob.did, imgCid)
    check(viaAv.ok && viaAv.bytes.equals(S.img) && viaAv.type === 'image/png', 'the appview serves the image to a member', `${viaAv.status} ${viaAv.error}`)
  }, { needs: ['1.create-board'] })

  await step('3.lurker-outsider', async (check) => {
    const B = S.board
    const cred = await S.daveC.credential(B)
    const bobRepo = await (await cred.repoClient(S.bob.did)).com.atproto.space.listRecords({ space: B, repo: S.bob.did })
    check(bobRepo.data.records.some((r) => `${S.board}/${S.bob.did}/${r.collection}/${r.rkey}` === S.P1 || r.uri === S.P1), 'dave reads bob\'s repo with his credential')
    const posts = await S.av.dave.getPosts(B, 'new')
    check(posts.posts.length === 3, 'dave reads the board through the appview', posts.posts.length)
    const before = (await listReposAll(cred, B)).get(S.dave.did)
    const own = await attempt(() => S.daveC.comment(B, S.P1, `lurker talking ${SENTINEL}`))
    // reference rule: a read-only member may write its own repo; the authority just doesn't track it
    if (own.ok || own === undefined) rep.note(`${label}: dave's (read-only) comment was accepted by his host (reference rule: write governs tracking only)`)
    S.daveVote = await attempt(() => S.daveC.vote(B, S.P2, 'up'))
    await sleep(2500)
    const listed = await listReposAll(cred, B)
    check(!before && !listed.has(S.dave.did), 'the authority does not track the lurker\'s repo')
    const th = await S.av.dave.getPostThread(S.P1)
    check(!JSON.stringify(th).includes('lurker talking'), "the lurker's comment never shows on the appview")
    const p2 = (await S.av.dave.getPosts(B, 'new')).posts.find((p) => p.uri === S.P2)
    check(p2?.score === 0, "the lurker's vote doesn't count", JSON.stringify(p2))
    const other = await attempt(() => S.dave.client.com.atproto.space.createRecord({ space: B, repo: S.bob.did, collection: C.comment, record: { $type: C.comment, subject: S.P1, body: 'x', createdAt: new Date().toISOString() } }))
    check(!other.ok, "dave can't write into bob's repo", errName(other))

    const eveCred = await attempt(() => credentialFor(S.eve, B).then((data) => ({ data })))
    check(!eveCred.ok && eveCred.error === 'SpaceNotFound', 'eve (not a member) gets no credential (SpaceNotFound)', errName(eveCred))
    const eveRead = await attempt(() => S.eve.client.com.atproto.space.listRecords({ space: B, repo: S.bob.did }))
    check(!eveRead.ok, "eve can't read bob's board repo with her own auth", errName(eveRead))
    const evil = await S.eveC.createBoard(`${SENTINEL}evil`, { name: 'evil' })
    const evilCred = await S.eveC.credential(evil)
    const wrongBoard = await S.av.eve.call('dev.example.boards.getPosts', null, { params: { board: B }, cred: evilCred })
    check(wrongBoard.status === 401, "a credential for eve's own board doesn't open rustaceans on the appview", errName(wrongBoard))
    const stolenKey = new SpaceCred(B, cred.credential, await P256Keypair.create())
    const forged = await S.av.eve.call('dev.example.boards.getPosts', null, { params: { board: B }, cred: stolenKey })
    check(forged.status === 401, "dave's credential signed with eve's key is refused by the appview", errName(forged))
    const noIndex = await S.av.eve.call('dev.example.boards.indexBoard', null, { body: { board: evil }, cred: evilCred })
    check(!noIndex.ok && noIndex.error === 'NotAMember', "the appview can't index a board it isn't a member of", errName(noIndex))
  }, { needs: ['2.post-comment-vote'] })

  await step('4.edit-delete-converge', async (check) => {
    const B = S.board
    const av = S.av.dave
    S.appview.paused = true // only notifies may move the appview here
    const lat = []
    const notifies0 = S.appview.boards.get(B).syncer.stats.notifies
    const visible = async (what, fn) => {
      const t = performance.now()
      await waitFor(what, fn, { timeoutMs: 15_000, intervalMs: 5 })
      lat.push(performance.now() - t)
    }
    try {
      for (let i = 0; i < 10; i++) {
        const c = await S.carolC.comment(B, S.P2, `answer ${i} ${SENTINEL}`)
        await visible(`carol's comment ${i}`, async () => JSON.stringify((await av.getPostThread(S.P2)).replies).includes(c.uri))
        const e = await S.bobC.editPost(S.P2, { body: `edit ${i} ${SENTINEL}` })
        await visible(`bob's edit ${i}`, async () => (await av.getPostThread(S.P2)).post.cid === e.cid)
        const d = await S.bobC.comment(B, S.P2, `oops ${i}`)
        await visible(`bob's comment ${i}`, async () => JSON.stringify((await av.getPostThread(S.P2)).replies).includes(d.uri))
        await S.bobC.deleteRecord(d.uri)
        await visible(`bob's delete ${i}`, async () => !JSON.stringify((await av.getPostThread(S.P2)).replies).includes(d.uri))
      }
      const conv = await converge(() => compareView(av, B, model(), { karma: [S.alice.did, S.bob.did, S.carol.did] }))
      check(!conv.diffs.length, 'the appview equals the model after 40 edits, comments and deletes', conv.diffs.slice(0, 4).join('; '))
      const p2 = (await av.getPostThread(S.P2)).post
      check(p2.body === `edit 9 ${SENTINEL}` && !!p2.editedAt, 'the post shows the last edit, marked edited')
    } finally {
      S.appview.paused = false
    }
    const st = S.appview.boards.get(B).syncer.stats
    check(st.notifies - notifies0 >= 40, 'every change arrived as a forwarded notify', st.notifies - notifies0)
    check(st.mismatchFallbacks === 0, 'no LtHash mismatch fell back to getRepo', JSON.stringify(st))
    check(!S.appview.boards.get(B).syncer.violations.length, 'no sync protocol violations', S.appview.boards.get(B).syncer.violations.join('; '))
    const s = summarize(lat)
    rep.metrics[`${label}.ack_to_appview_ms`] = s
    rep.note(`${label}: write ack -> visible on the appview (notify-driven, poll off): p50 ${s.p50?.toFixed(1)} ms, p99 ${s.p99?.toFixed(1)} ms, n ${s.n}`)
    check(s.p99 < 2000, 'p99 ack -> visible under 2 s', s.p99)
  }, { needs: ['2.post-comment-vote'] })

  await step('5.remove-member', async (check) => {
    const B = S.board
    const oldCred = await S.carolC.credential(B)
    const daveCred = await S.daveC.credential(B)
    const listed0 = (await listReposAll(daveCred, B)).get(S.carol.did)
    await S.aliceC.removeMember(B, S.carol.did)
    const members = await S.aliceC.listMembers(B)
    check(!members.some((m) => m.did === S.carol.did), 'carol is off the member list')
    const c = await attempt(() => credentialFor(S.carol, B).then((data) => ({ data })))
    check(!c.ok && c.error === 'SpaceNotFound', 'carol gets no new credential (SpaceNotFound)', errName(c))
    const late = await attempt(() => S.carolC.comment(B, S.P1, `after removal ${SENTINEL}`))
    rep.note(`${label}: carol's write after removal: ${late.ok !== false ? 'accepted by her host' : `refused (${errName(late)})`}`)
    await sleep(2500)
    const listed1 = (await listReposAll(daveCred, B)).get(S.carol.did)
    check(listed0 && !listed1, 'removeMember drops carol from the writer set: listRepos no longer names her', `${listed0?.repoRev} -> ${listed1?.repoRev}`)
    const conv = await converge(() => compareView(S.av.dave, B, model(), { karma: [S.alice.did, S.bob.did, S.carol.did] }))
    check(!conv.diffs.length, `the appview hides carol's posts, comments and votes (${conv.ms} ms)`, conv.diffs.slice(0, 4).join('; '))
    const p1 = (await S.av.dave.getPosts(B, 'new')).posts.find((p) => p.uri === S.P1)
    check(p1?.score === 2 && p1.comments === 1, "P1 back to 2 without carol's down vote, 1 comment (r1)", JSON.stringify(p1))
    const th = await S.av.dave.getPostThread(S.P1)
    check(th.replies[0]?.deleted && th.replies[0].uri === S.c1 && th.replies[0].replies[0]?.uri === S.r1, "r1 hangs under a placeholder for carol's hidden c1", JSON.stringify(normTree(th.replies)))
    const oldRead = await attempt(async () => (await oldCred.repoClient(S.bob.did)).com.atproto.space.listRecords({ space: B, repo: S.bob.did }))
    rep.note(`${label}: carol's credential minted before removal ${oldRead.ok ? `still reads bob's repo until it expires (${Math.round(oldCred.expiresInMs() / 1000)} s left)` : `is refused (${errName(oldRead)})`}; the credential names no holder, so neither host nor appview can tell it's hers without a revocation`)
    // the appview's syncer still holds the copy it had (removal isn't announced), which is why boards hides removed members by settings
    const held = S.appview.boards.get(B)?.syncer.repos.has(S.carol.did)
    rep.note(`${label}: after carol's removal the appview's syncer ${held ? 'still holds' : 'no longer holds'} her repo; a syncer starting now never pulls it (listRepos doesn't name her)`)
  }, { needs: ['2.post-comment-vote'] })

  await step('6.takedown', async (check) => {
    const B = S.board
    const av = S.av.dave
    const set = (applied) =>
      rawXrpc(S.bob.base, 'com.atproto.admin.updateSubjectStatus', {
        method: 'POST',
        headers: { authorization: adminAuth() },
        body: { subject: { $type: 'com.atproto.repo.strongRef', uri: S.P1, cid: (truth.repo(B, S.bob.did).get(pathOf(S.P1))).cid }, takedown: { applied, ref: applied ? 'boards-tos' : undefined } },
      })
    const on = await set(true)
    check(on.ok, 'the operator takes down P1', `${on.status} ${on.error} ${on.message}`)
    if (!on.ok) return
    S.hidden.add(`${S.bob.did}/${pathOf(S.P1)}`)
    try {
      const cred = await credentialFor(S.dave, B)
      const cl = await cred.repoClient(S.bob.did)
      const u = parseRecordUri(S.P1)
      const g = await attempt(() => cred.macRead(S.bob.did, RECORD_MAC_TYPE, (c, opts) => c.com.atproto.space.getRecord({ space: B, repo: S.bob.did, collection: u.collection, rkey: u.rkey }, opts)).then((r) => r.res))
      check(!g.ok && g.error === 'RecordNotFound', 'getRecord answers RecordNotFound', errName(g))
      const lr = await cl.com.atproto.space.listRecords({ space: B, repo: S.bob.did, limit: 100 })
      check(!lr.data.records.some((r) => r.uri === S.P1 || String(r.rkey) === u.rkey), 'listRecords leaves it out')
      const blob = await attempt(() => cl.com.atproto.space.getBlob({ space: B, repo: S.bob.did, cid: S.imgCid }))
      check(!blob.ok && blob.error === 'BlobNotFound', 'its image answers BlobNotFound', errName(blob))
      const head = await headOf(cred, B, S.bob.did)
      const listedData = (await listReposAll(cred, B)).get(S.bob.did)?.data
      rep.note(`${label}: during the takedown, listRepos' data for bob ${Buffer.from(listedData ?? []).equals(Buffer.from(head.data)) ? 'matches' : 'differs from'} his takedown-adjusted head (same rev ${head.rev}); syncers learn of a takedown only by pulling the repo`)
      const conv = await converge(() => compareView(av, B, model(), { karma: [S.alice.did, S.bob.did] }), 20_000, 200)
      check(!conv.diffs.length, `the appview converges on the board without P1 (${conv.ms} ms, poll-driven)`, conv.diffs.slice(0, 4).join('; '))
      rep.metrics[`${label}.takedown_to_appview_ms`] = conv.ms
      const img = await S.av.dave.getImage(B, S.bob.did, S.imgCid)
      check(!img.ok, "the appview can't serve its image", `${img.status}`)
      const before = await rawXrpc(S.bob.base, 'vlpds.admin.getAuditLog', { params: { did: S.bob.did, limit: 100 }, headers: { authorization: adminAuth() } })
      const op = await rawXrpc(S.bob.base, 'vlpds.admin.getSpaceRecord', { params: { space: B, repo: S.bob.did, collection: u.collection, rkey: u.rkey, reason: 'ToS review' }, headers: { authorization: adminAuth() } })
      check(op.ok && op.json?.takendown === true && op.json?.value?.title?.includes(SENTINEL), 'the operator reads it with vlpds.admin.getSpaceRecord, flagged takendown', `${op.status} ${op.error} ${JSON.stringify(op.json).slice(0, 200)}`)
      const after = await rawXrpc(S.bob.base, 'vlpds.admin.getAuditLog', { params: { did: S.bob.did, limit: 100 }, headers: { authorization: adminAuth() } })
      if (before.ok && after.ok) {
        const seen = new Set(before.json.entries.map((e) => e.id))
        check(after.json.entries.some((e) => !seen.has(e.id) && JSON.stringify(e).includes(u.rkey)), 'the read is in the audit log')
      } else rep.note(`${label}: getAuditLog ${before.status}; audit unchecked`)
      const asMember = await attempt(() => cred.macRead(S.bob.did, RECORD_MAC_TYPE, (c, opts) => c.com.atproto.space.getRecord({ space: B, repo: S.bob.did, collection: u.collection, rkey: u.rkey }, opts)).then((r) => r.res))
      check(!asMember.ok, 'members still can\'t read it')
    } finally {
      const off = await set(false)
      check(off.ok, 'reversal', `${off.status} ${off.error}`)
      S.hidden.clear()
    }
    const back = await converge(() => compareView(av, B, model(), { karma: [S.alice.did, S.bob.did] }), 20_000, 200)
    check(!back.diffs.length, `after reversal the appview shows P1 again (${back.ms} ms)`, back.diffs.slice(0, 4).join('; '))
    const img = await S.av.dave.getImage(B, S.bob.did, S.imgCid)
    check(img.ok && img.bytes.equals(S.img), 'and its image')
  }, { needs: ['2.post-comment-vote'], skip: P.bob === 'vlpds' ? undefined : 'record takedown is a vlpds extension; bob is not on vlpds' })

  await step('8.revoke', async (check) => {
    const B = S.board
    const stolen = await credentialFor(S.dave, B)
    const read = async () => attempt(async () => (await stolen.repoClient(S.bob.did)).com.atproto.space.listRecords({ space: B, repo: S.bob.did, limit: 1 }))
    const avRead = () => S.av.dave.call('dev.example.boards.getBoard', null, { params: { board: B }, cred: stolen })
    check((await read()).ok && (await avRead()).ok, 'the stolen credential reads before revocation')
    const targets = new Map()
    for (const a of [S.alice, S.bob, S.carol]) targets.set(a.did, a.base)
    const t0 = performance.now()
    for (const [did, base] of targets) {
      const r = await revokeCredentials(S.alice, B, [stolen.jti], { aud: did, url: base })
      check(r.ok, `revocation accepted for ${did === S.bob.did ? 'bob' : did === S.alice.did ? 'alice' : 'carol'}'s repo host`, `${r.status} ${r.error} ${r.message}`)
    }
    const rv = await revokeCredentials(S.alice, B, [stolen.jti], { aud: S.appview.did, url: `http://localhost:${NOTIFY_PORT}` })
    check(rv.ok, 'and by the appview', `${rv.status} ${rv.error}`)
    const failed = await waitFor('reads with the revoked credential to fail', async () => {
      const r = await read()
      return !r.ok && r
    }, { timeoutMs: 10_000, intervalMs: 20 }).catch(() => null)
    const ms = performance.now() - t0
    check(failed?.error === 'CredentialRevoked', `bob's host refuses it with CredentialRevoked (${Math.round(ms)} ms after the first revoke)`, failed && errName(failed))
    rep.metrics[`${label}.revoke_to_refused_ms`] = Math.round(ms)
    const a = await avRead()
    check(a.status === 401 && a.error === 'CredentialRevoked', 'the appview refuses it too', errName(a))
    const fresh = await credentialFor(S.dave, B)
    const ok = await attempt(async () => (await fresh.repoClient(S.bob.did)).com.atproto.space.listRecords({ space: B, repo: S.bob.did, limit: 1 }))
    check(ok.ok, "dave's fresh credential still reads", errName(ok))
  }, { needs: ['2.post-comment-vote'] })

  await step('10.scale', async (check) => scale(check), { needs: ['0.setup'] })
  await step('11.fault', async (check) => fault(check), { needs: ['10.scale'], skip: CLUSTER ? undefined : 'CLUSTER=1 only' })

  await step('9.delete-board', async (check) => {
    const B = S.board
    await S.aliceC.deleteBoard(B)
    const c = await attempt(() => credentialFor(S.bob, B).then((data) => ({ data })))
    check(!c.ok && c.error === 'SpaceDeleted', 'getSpaceCredential answers SpaceDeleted', errName(c))
    const told = await waitFor('notifySpaceDeleted', () => S.svc.callsTo('com.atproto.space.notifySpaceDeleted', B).length > 0, { timeoutMs: 15_000 }).catch(() => false)
    check(told, 'the appview got notifySpaceDeleted')
    const gone = await converge(async () => {
      const r = await S.av.bob.call('dev.example.boards.getBoard', null, { params: { board: B }, cred: (await S.bobC.credential(B).catch(() => null)) ?? S.bobC.creds.get(B) })
      return r.error === 'BoardNotFound' ? [] : [`getBoard ${r.status} ${r.error}`]
    }, 15_000, 200)
    check(!gone.diffs.length, 'the appview drops the board (BoardNotFound)', gone.diffs.join())
    check(S.appview.boards.get(B)?.syncer.repos.size === 0, 'and holds none of its records')
    const own = await attempt(() => S.bob.client.com.atproto.space.listRecords({ space: B, repo: S.bob.did }))
    check(own.ok && own.data.records.length > 0, "bob's own space repo stays (reference rule: deleteSpace sweeps the authority's rows only)", errName(own))
  }, { needs: ['1.create-board'] })

  await step('7.privacy', async (check) => {
    await sleep(1000)
    const backfills = []
    for (const t of S.taps) {
      const b = new FirehoseTap(t.base, `${t.label} cursor 0`)
      await b.open(0)
      backfills.push(b)
    }
    for (const b of backfills) await b.drain()
    for (const t of [...S.taps, ...backfills]) {
      check(!t.hits.length, `${t.label}: no board content on the firehose (${t.frames} frames)`, t.hits[0])
      t.close()
    }
    const dirty = []
    const moved = []
    for (const a of S.actors) {
      const leaks = await checkAuthor(a.base, a.did, a === S.bob ? S.spaceBlobs : [])
      dirty.push(...leaks)
      if (S.revs0.has(a.did) && (await publicRev(a)) !== S.revs0.get(a.did)) moved.push(`${a}`)
    }
    check(!dirty.length, `getRepo / listBlobs / getBlob clean for ${S.actors.length} accounts`, dirty.slice(0, 3).join('; '))
    check(!moved.length, "board activity left every member's public repo rev alone", moved.join(', '))
  }, { needs: ['0.setup'] })

  await S.appview?.stop()
  await S.svc?.stop()
  for (const t of S.taps) t.close()

  // ---- 10 + 11 ----

  async function scale(check) {
    const rand = mulberry32(SEED)
    const pick = (arr) => arr[Math.floor(rand() * arr.length)]
    const crowd = [S.alice]
    for (let i = 1; i < SCALE.members; i++) crowd.push(await Actor.create(P.crowd[i % P.crowd.length], `m${i}`, { scope: SCOPES.member }))
    S.actors.push(...crowd.slice(1))
    for (const a of crowd.slice(1)) S.revs0.set(a.did, await publicRev(a))
    const clients = crowd.map((a) => (a === S.alice ? S.aliceC : new BoardsClient(a, { onWrite })))
    const B = await S.aliceC.createBoard(`${SENTINEL}scale`, { name: 'crab-rave', flairs: ['meme', 'news'] })
    S.scaleBoard = B
    for (const a of crowd.slice(1)) await S.aliceC.addMember(B, a.did)
    await S.aliceC.addMember(B, S.bot.did, { write: false })
    const tracked = new Set(crowd.map((a) => a.did))
    await S.av.alice.indexBoard(B)

    // the workload, seeded; rkeys are chosen up front so later ops can name earlier records
    const base = Date.parse('2026-10-01T00:00:00Z')
    const posts = []
    const comments = [] // { uri, post }
    const ops = []
    const voted = new Map()
    let left = { post: SCALE.posts, comment: SCALE.comments, vote: SCALE.votes }
    for (let i = 0; left.post + left.comment + left.vote > 0; i++) {
      const total = left.post + left.comment + left.vote
      let r = rand() * total
      let kind = r < left.post ? 'post' : r < left.post + left.comment ? 'comment' : 'vote'
      if (posts.length < 5 && left.post) kind = 'post'
      left[kind]--
      const who = Math.floor(rand() * crowd.length)
      const did = crowd[who].did
      const createdAt = new Date(base + i * 60_000).toISOString()
      if (kind === 'post') {
        const rkey = tid(base + i)
        const uri = `${B}/${did}/${C.post}/${rkey}`
        posts.push(uri)
        ops.push({ who, kind, rkey, value: { title: `post ${i} ${SENTINEL}`, body: `body ${i}`, flair: rand() < 0.3 ? pick(['meme', 'news', 'other']) : undefined, createdAt } })
      } else if (kind === 'comment') {
        const post = pick(posts)
        const siblings = comments.filter((c) => c.post === post)
        const parent = siblings.length && rand() < 0.5 ? pick(siblings).uri : undefined
        const rkey = tid(base + i)
        comments.push({ uri: `${B}/${did}/${C.comment}/${rkey}`, post })
        ops.push({ who, kind, rkey, post, parent, body: `comment ${i} ${SENTINEL}`, createdAt })
      } else {
        const subject = rand() < 0.7 || !comments.length ? pick(posts) : pick(comments).uri
        const k = `${did} ${subject}`
        if (voted.has(k) && rand() < 0.15) {
          voted.delete(k)
          ops.push({ who, kind: 'unvote', subject })
        } else {
          voted.set(k, true)
          ops.push({ who, kind, subject, direction: rand() < 0.7 ? 'up' : 'down', createdAt })
        }
      }
    }

    const locks = new Map()
    const stats = { acked: 0, refused: 0, uncertain: 0, vlpdsAcked: 0, ackedDuringOutage: 0 }
    const m0 = await storeMetrics(env)
    let next = 0
    const faultAt = CLUSTER ? Math.floor(ops.length * 0.3) : -1
    S.fault = null
    const t0 = performance.now()
    const run = async (op) => {
      const cl = clients[op.who]
      if (op.kind === 'post') return cl.post(B, { ...op.value, rkey: op.rkey })
      if (op.kind === 'comment') return cl.comment(B, op.post, op.body, { parent: op.parent, createdAt: op.createdAt, rkey: op.rkey })
      if (op.kind === 'vote') return cl.vote(B, op.subject, op.direction, { createdAt: op.createdAt })
      return cl.unvote(B, op.subject)
    }
    const worker = async () => {
      while (next < ops.length) {
        const i = next++
        const op = ops[i]
        if (i === faultAt) S.fault = fireFault()
        const turn = locks.get(op.who) ?? Promise.resolve()
        let release
        locks.set(op.who, new Promise((r) => (release = r)))
        await turn
        try {
          const r = await attempt(() => run(op).then((data) => ({ data }))).catch((e) => ({ ok: false, status: 0, error: String(e?.message ?? e) }))
          if (r.ok) {
            stats.acked++
            if (crowd[op.who].host === 'vlpds') stats.vlpdsAcked++
            if (S.fault && !S.fault.restarted) stats.ackedDuringOutage++
          } else if (r.status >= 400 && r.status < 500 && !['RepoLoading', 'ShardMoved'].includes(r.error)) {
            stats.refused++
            if (stats.refused <= 5) rep.note(`${label}: scale write refused: ${op.kind} ${r.status} ${r.error}`)
          } else {
            stats.uncertain++
            const path = op.kind === 'post' ? `${C.post}/${op.rkey}` : op.kind === 'comment' ? `${C.comment}/${op.rkey}` : `${C.vote}/${voteRkey(op.subject)}`
            truth.repo(B, crowd[op.who].did).set(path, UNCERTAIN)
          }
        } finally {
          release()
        }
      }
    }
    await Promise.all(Array.from({ length: CONC }, worker))
    const wallS = (performance.now() - t0) / 1000
    if (S.fault) await S.fault.done
    const m1 = await storeMetrics(env)

    // resolve uncertain writes from each host's own listing, and check nothing acked was lost (I1)
    const lost = []
    for (const a of crowd) {
      const own = await listOwn(a, B)
      const want = truth.repo(B, a.did)
      for (const [p, r] of [...want]) {
        if (r === UNCERTAIN) {
          if (own.has(p)) want.set(p, own.get(p))
          else want.delete(p)
        } else if (own.get(p)?.cid !== r.cid) lost.push(`${a}: ${p} acked ${r.cid}, host ${own.get(p)?.cid}`)
      }
      for (const p of own.keys()) if (!want.has(p)) lost.push(`${a}: ${p} on the host but never acked`)
    }
    check(!lost.length, `every acked write is on its host (${stats.acked} acked, ${stats.uncertain} uncertain)`, lost.slice(0, 5).join('; '))
    S.scaleLost = lost

    const tq = performance.now()
    const want = truth.model(B, { tracked })
    const quick = await converge(() => compareView(S.av.alice, B, want, { threads: false, sorts: ['new'] }), CLUSTER ? 240_000 : 60_000, 250)
    const catchUp = Math.round(performance.now() - tq)
    check(!quick.diffs.length, `the appview's posts, scores and counts match (${catchUp} ms after the last ack)`, quick.diffs.slice(0, 4).join('; '))
    const full = await converge(() => compareView(S.av.alice, B, want, { karma: [...tracked] }), 60_000, 1000)
    check(!full.diffs.length, `every thread, sort and karma matches (${want.posts.size} posts, ${want.comments.size} comments)`, full.diffs.slice(0, 4).join('; '))
    const sy = S.appview.boards.get(B).syncer
    check(!sy.violations.length, 'no sync protocol violations', sy.violations.slice(0, 3).join('; '))
    // a killed node's counters leave the sum (and restart at 0), so a fault run has no bucket-op figure
    const storeOps = S.fault ? null : m1.store - m0.store
    const per = (n) => (storeOps === null ? null : +(storeOps / Math.max(1, n)).toFixed(3))
    const opsBy = {}
    if (storeOps !== null) for (const [k, v] of Object.entries(m1.by)) if (v - (m0.by[k] ?? 0)) opsBy[k] = v - (m0.by[k] ?? 0)
    const out = {
      members: crowd.length,
      hosts: P.crowd,
      ops: ops.length,
      ...stats,
      wall_s: +wallS.toFixed(2),
      writes_per_s: +(stats.acked / wallS).toFixed(1),
      appview_catch_up_ms: catchUp,
      appview_full_check_ms: full.ms,
      vlpds_store_ops: storeOps,
      vlpds_store_ops_per_board_write: per(stats.acked),
      vlpds_store_ops_per_vlpds_write: per(stats.vlpdsAcked),
      vlpds_store_ops_by: opsBy,
      appview_sync: { ...sy.stats },
    }
    rep.metrics[`${label}.scale`] = out
    rep.note(`${label}: scale ${out.acked} writes in ${out.wall_s} s (${out.writes_per_s}/s at ${CONC} in flight), appview caught up ${catchUp} ms after the last ack, ${out.vlpds_store_ops_per_vlpds_write ?? 'n/a (a node restarted)'} vlpds bucket ops per vlpds-hosted write`)
    S.scale = { B, crowd, tracked, stats }
  }

  function fireFault() {
    const f = { restarted: false }
    f.done = (async () => {
      log(`[${label}] FAULT kill -9 vlpds n1`)
      f.killedAt = performance.now()
      await env.vlpds.killNode(1, 'SIGKILL')
      await sleep(20_000)
      await env.vlpds.restartNode(1)
      f.restarted = true
      f.downMs = Math.round(performance.now() - f.killedAt)
    })()
    return f
  }

  async function fault(check) {
    const { B, crowd, stats } = S.scale
    check(!!S.fault?.restarted, `n1 was killed mid-run and came back (${S.fault?.downMs} ms down)`)
    check(stats.ackedDuringOutage > 0, `the board kept taking writes while n1 was down (${stats.ackedDuringOutage} acked)`)
    check(!S.scaleLost.length, 'no acked write was lost', S.scaleLost.slice(0, 3).join('; '))
    // the authority tracks every writer at its head, eventually (outbox retries)
    const cred = await credentialFor(S.alice, B)
    const deadline = Date.now() + 240_000
    let behind = []
    for (;;) {
      const listed = await listReposAll(cred, B)
      behind = []
      for (const a of crowd) {
        if (!truth.repo(B, a.did).size && !listed.has(a.did)) continue
        const head = await headOf(cred, B, a.did)
        if (listed.get(a.did)?.repoRev !== head.rev) behind.push(`${a}: listed ${listed.get(a.did)?.repoRev} head ${head.rev}`)
      }
      if (!behind.length || Date.now() > deadline) break
      await sleep(2000)
    }
    check(!behind.length, 'listRepos has every writer at its head after failover', behind.slice(0, 3).join('; '))
    rep.metrics[`${label}.fault`] = { down_ms: S.fault?.downMs, acked_during_outage: stats.ackedDuringOutage, uncertain: stats.uncertain }
  }
}

async function main() {
  const want = process.argv.slice(2).filter((a) => !a.startsWith('-'))
  const configs = want.length ? want : Object.keys(CONFIGS)
  const rep = new Report(process.env.REPORT ?? (CLUSTER ? 'boards-cluster' : 'boards'), {
    run: RUN,
    vlpds: process.env.VLPDS_REV ?? '(none)',
    cluster: CLUSTER,
    seed: SEED,
    scale: SCALE,
    configs,
  })
  const env = {}
  if (configs.some(usesVlpds)) env.vlpds = await new Vlpds({ cluster: CLUSTER, memory: !!process.env.MEMORY }).start()
  try {
    env.lexicons = env.vlpds ? await setupLexicons(env) : null
    rep.meta.lexicons = env.lexicons ?? (env.vlpds ? 'no --lexicon-authority-override in this binary' : 'no vlpds in this run')
    for (const cfg of configs) {
      if (!CONFIGS[cfg]) throw new Error(`unknown config ${cfg}`)
      setTimingScope(cfg)
      await runConfig(rep, cfg, env)
    }
  } finally {
    log(`report: ${rep.write()}`)
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
