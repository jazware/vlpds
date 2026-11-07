// Randomized Spaces workload with an invariant checker (README.md), and with
// FAULTS=1 the fault sim. A seed fixes every choice the driver makes (who
// writes what where, membership changes, when faults fire); hosts' own
// timing still varies, so a failing seed reproduces the workload, not the
// interleaving.
//
//   node sim.mjs [seed] [scale]       scale: small | medium | large | <ops>
//   HOSTS=ref-a,ref-b (all-ref: validates the harness) | ref-a,ref-b,vlpds (default with VLPDS_BIN)
//   FAULTS=1: notify drops/delays/duplicates on both hops, vlpds kill -9 and
//   SIGTERM mid-burst (CLUSTER=1: a node dies and its shards move), syncer restarts
//
// Invariants, checked after the workload and a quiet period:
//   I1 no lost acked write: every repo host's own listing equals the acked writes
//   I2 the authority tracks every writer at its latest repoRev (notify eventually delivered)
//   I3 every syncer converges: for each repo listRepos names, the syncer's copy is
//      the acked state (active writers) and its LtHash equals the verified commit
//   I4 spaceRev: strictly ascending in listRepos; no spaceRev assigned to two
//      different (repo, repoRev); the prevSpaceRev chain never forks
//   I5 syncers never saw a protocol violation (cursor, ordering, rev going back)
import { Actor, RUN } from './lib/actor.mjs'
import { COLL, HOSTS, PORTS, log } from './lib/env.mjs'
import { attempt, notImplemented, sleep, setTimingScope } from './lib/http.mjs'
import { setService } from './lib/identity.mjs'
import { FaultProxy } from './lib/faultproxy.mjs'
import { NotifyService } from './lib/notifysvc.mjs'
import { Report, summarize } from './lib/report.mjs'
import { createSpace, credentialFor, headOf, putMember, spaceUri } from './lib/space.mjs'
import { Syncer, hashEq } from './lib/syncer.mjs'
import { Vlpds } from './lib/vlpds.mjs'

const FAULTS = process.env.FAULTS === '1'
const seed = Number(process.argv[2] ?? process.env.SEED ?? Date.now() % 1e6)
const scaleArg = process.argv[3] ?? process.env.SCALE ?? 'small'
const SCALES = {
  small: { spaces: 3, members: 4, syncers: 2, ops: 300, conc: 6 },
  medium: { spaces: 6, members: 6, syncers: 3, ops: 1500, conc: 12 },
  large: { spaces: 12, members: 8, syncers: 4, ops: 6000, conc: 24 },
}
const SC = SCALES[scaleArg] ?? { ...SCALES.small, ops: Number(scaleArg) || 300 }
const hostList = (process.env.HOSTS ?? (process.env.VLPDS_BIN ? 'ref-a,ref-b,vlpds' : 'ref-a,ref-b')).split(',')

function mulberry32(a) {
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const rand = mulberry32(seed)
const pick = (arr) => arr[Math.floor(rand() * arr.length)]
const chance = (p) => rand() < p

const mode = FAULTS ? 'fault' : 'sim'
const rep = new Report(process.env.REPORT ?? mode, { run: RUN, seed, scale: scaleArg, ...SC, hosts: hostList, faults: FAULTS, cluster: !!process.env.CLUSTER, vlpds: process.env.VLPDS_REV ?? '(none)' })
const cfg = `${hostList.join('+')}${FAULTS ? ' faults' : ''}`

const UNCERTAIN = Symbol('uncertain')
class Repo {
  constructor(space, actor) {
    this.space = space
    this.actor = actor
    this.truth = new Map() // path -> cid | UNCERTAIN
    this.acked = 0
    this.uncertain = 0
    this.lastAck = 0
  }
}

async function main() {
  const env = { svcs: [], proxies: [], hostProxies: {} }
  const stats = { ops: 0, acked: 0, failed: 0, uncertain: 0, membership: 0, faultsFired: [] }
  const ackTimes = [] // { space, did, t }
  try {
    if (hostList.includes('vlpds')) env.vlpds = await new Vlpds({ cluster: !!process.env.CLUSTER, memory: !!process.env.MEMORY }).start()

    // notify receivers, each behind a fault proxy (pass-through unless FAULTS)
    for (let k = 0; k < SC.syncers; k++) {
      const svc = new NotifyService(PORTS.syncer + k, { publicPort: PORTS.syncerProxy + k })
      const px = await new FaultProxy(PORTS.syncerProxy + k, `http://127.0.0.1:${PORTS.syncer + k}`).start()
      px.rand = mulberry32(seed + 100 + k)
      env.svcs.push(await svc.start())
      env.proxies.push(px)
    }

    let world
    setTimingScope(`${cfg} setup`)
    await rep.step(cfg, 'setup', async (check) => {
      world = await setup(check, env)
    })
    if (rep.status(cfg, 'setup') === 'pass') await afterSetup(world, env, stats, ackTimes)
  } catch (e) {
    const ni = notImplemented(e)
    if (!ni) throw e
    rep.rows.push({ config: cfg, step: 'setup', status: 'ni', detail: ni.message, ms: 0, checks: [] })
  } finally {
    log(`report: ${rep.write()}`)
    for (const s of env.svcs) await s.stop()
    for (const p of [...env.proxies, ...Object.values(env.hostProxies)]) await p.stop()
    if (env.vlpds && process.env.KEEP !== '1') await env.vlpds.stop()
  }
  console.log(`\n${rep.markdown()}`)
  process.exit(rep.failed().length ? 1 : rep.rows.some((r) => r.status === 'ni') ? 3 : 0)
}

async function afterSetup(world, env, stats, ackTimes) {
  if (FAULTS) {
    for (const px of env.proxies) px.rules = { drop: 0.2, dup: 0.2, delayMs: [0, 1500] }
    for (const px of Object.values(env.hostProxies)) px.rules = { drop: 0.3, dup: 0.1, delayMs: [0, 800] }
  }

  setTimingScope(`${cfg} workload`)
  await rep.step(cfg, 'workload', async (check) => {
    await workload(world, env, stats, ackTimes)
    check(stats.acked > 0, 'some writes were acked', JSON.stringify(stats))
  }, { needs: ['setup'] })

  if (FAULTS) {
    for (const px of [...env.proxies, ...Object.values(env.hostProxies)]) px.rules = { drop: 0, dup: 0, delayMs: [0, 0] }
  }

  setTimingScope(`${cfg} invariants`)
  await rep.step(cfg, 'invariants', async (check) => {
    await invariants(world, env, check)
  }, { needs: ['workload'] })

  const lat = notifyLatencies(world, env, ackTimes)
  rep.metrics.notify_ms = summarize(lat)
  rep.metrics.stats = stats
  rep.metrics.syncers = world ? Object.fromEntries(world.syncers.map((s) => [s.name, s.stats])) : {}
  rep.metrics.proxies = Object.fromEntries([...env.proxies.map((p, i) => [`syncer${i}`, p.stats]), ...Object.entries(env.hostProxies).map(([h, p]) => [`authority@${h}`, p.stats])])
}

async function setup(check, env) {
  const nAcct = Math.max(SC.members + 2, 6)
  const actors = []
  for (let i = 0; i < nAcct; i++) actors.push(await Actor.create(hostList[i % hostList.length], `s${i}`))
  check(actors.length === nAcct, `${nAcct} accounts across ${hostList.join(', ')}`)

  const spaces = []
  for (let n = 0; n < SC.spaces; n++) {
    const authority = actors[n % actors.length]
    if (FAULTS && !env.hostProxies[authority.host]) {
      // the writer -> authority hop goes through a proxy: the authority's
      // #atproto_pds (its space host) names it, signed with the host's test
      // rotation key; everything but notifyWrite passes straight through
      const port = PORTS.hostProxy[authority.host]
      const px = await new FaultProxy(port, HOSTS[authority.host].url, { match: /notifyWrite/ }).start()
      px.rand = mulberry32(seed + 200 + port)
      env.hostProxies[authority.host] = px
    }
    if (FAULTS && env.hostProxies[authority.host]) {
      try {
        await setService(authority.did, authority.host, 'atproto_pds', 'AtprotoPersonalDataServer', `http://localhost:${env.hostProxies[authority.host].port}`)
      } catch (e) {
        rep.note(`could not point ${authority}'s #atproto_pds at the fault proxy (${e.message}); its inbound notifies go direct`)
      }
    }
    const skey = `sim${RUN}n${n}`
    const uri = await createSpace(authority, skey)
    check(uri === spaceUri(authority.did, skey), `space ${n} created on ${authority.host}`)
    const others = actors.filter((a) => a !== authority).sort(() => rand() - 0.5)
    const writers = [authority, ...others.slice(0, SC.members - 1)]
    const reader = others[SC.members - 1] ?? others[0]
    for (const w of writers.slice(1)) await putMember(authority, uri, w, true, true)
    if (!writers.includes(reader)) await putMember(authority, uri, reader, true, false)
    spaces.push({ n, uri, authority, writers, reader, removed: new Set(), repos: new Map(writers.map((w) => [w.did, new Repo(uri, w)])) })
  }

  const syncers = []
  for (const sp of spaces) {
    for (let k = 0; k < SC.syncers; k++) {
      const s = new Syncer(`syncer${k}/space${sp.n}`, sp.uri, sp.reader)
      s.svc = k
      syncers.push(s)
      const cred = await credentialFor(sp.reader, sp.uri)
      await (await cred.hostClient()).com.atproto.space.registerNotify({ space: sp.uri, service: env.svcs[k].serviceRef })
      env.svcs[k].on((call) => {
        if (call.lxm === 'com.atproto.space.notifyWrite' && call.body.space === sp.uri) s.notify(call.body)
      })
      await s.sync()
    }
  }
  check(true, `${spaces.length} spaces x ${SC.syncers} registered syncers`)
  return { actors, spaces, syncers }
}

function newRkey() {
  return `r${Math.floor(rand() * 2 ** 40).toString(36)}`
}

async function workload(world, env, stats, ackTimes) {
  const { spaces, syncers } = world
  const total = SC.ops
  let next = 0
  const faultAt = FAULTS ? planFaults(total) : []

  const one = async () => {
    const i = next++
    if (i >= total) return false
    stats.ops++
    for (const f of faultAt.filter((f) => f.at === i)) fire(f, world, env, stats).catch((e) => rep.note(`fault ${f.kind}: ${e.message}`))
    const sp = pick(spaces)
    if (chance(0.03)) {
      await membership(sp, stats)
      return true
    }
    const w = pick(sp.writers)
    const repo = sp.repos.get(w.did)
    // one write at a time per repo, as an app does: concurrent writes to one
    // path would ack in an order the host needn't have applied them in
    const turn = repo.lock ?? Promise.resolve()
    let release
    repo.lock = new Promise((r) => (release = r))
    await turn
    try {
      await writeOne(i, sp, w, repo, stats, ackTimes)
    } finally {
      release()
    }
    return true
  }

  const writeOne = async (i, sp, w, repo, stats, ackTimes) => {
    const paths = [...repo.truth.keys()]
    const r = rand()
    let op
    if (r < 0.55 || paths.length === 0) op = { kind: 'create', path: `${COLL}/${newRkey()}` }
    else if (r < 0.75) op = { kind: 'update', path: pick(paths) }
    else if (r < 0.92) op = { kind: 'delete', path: pick(paths) }
    else op = { kind: 'batch' }
    const c = w.client.com.atproto.space
    const val = () => ({ $type: COLL, text: `${op.kind} ${i} ${seed}`, createdAt: new Date().toISOString() })
    const res = await attempt(async () => {
      if (op.kind === 'create' || op.kind === 'update') {
        const rkey = op.path.split('/')[1]
        const fn = op.kind === 'create' ? c.createRecord : c.putRecord
        return fn.call(c, { space: sp.uri, repo: w.did, collection: COLL, rkey, record: val() })
      }
      if (op.kind === 'delete') return c.deleteRecord({ space: sp.uri, repo: w.did, collection: COLL, rkey: op.path.split('/')[1] })
      op.writes = [
        { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: newRkey(), value: val() },
        { $type: 'com.atproto.space.applyWrites#create', collection: COLL, rkey: newRkey(), value: val() },
      ]
      return c.applyWrites({ space: sp.uri, repo: w.did, writes: op.writes })
    }).catch((e) => ({ ok: false, status: 0, error: String(e?.message ?? e) }))
    const paths2 = op.kind === 'batch' ? op.writes.map((x) => `${COLL}/${x.rkey}`) : [op.path]
    if (res.ok) {
      stats.acked++
      repo.acked++
      repo.lastAck = performance.now()
      if (!sp.removed.has(w.did)) repo.stale = false
      ackTimes.push({ space: sp.uri, did: w.did, t: repo.lastAck })
      if (op.kind === 'delete') repo.truth.delete(op.path)
      else if (op.kind === 'batch') op.writes.forEach((x, j) => repo.truth.set(`${COLL}/${x.rkey}`, String(res.data.results[j].cid)))
      else repo.truth.set(op.path, String(res.data.cid))
    } else if (res.status >= 400 && res.status < 500 && !['RepoLoading', 'ShardMoved'].includes(res.error)) {
      stats.failed++ // a definite refusal: nothing applied
      if (!(op.kind === 'create' && res.error === 'RecordAlreadyExists')) rep.note(`write refused: ${w} ${op.kind} ${res.status} ${res.error}`)
    } else {
      stats.uncertain++ // a crash, a 5xx or a dropped connection: either outcome is allowed
      repo.uncertain++
      for (const p of paths2) repo.truth.set(p, UNCERTAIN)
    }
  }

  const workers = Array.from({ length: SC.conc }, async () => {
    while (await one()) {}
  })
  await Promise.all(workers)
  await Promise.all(syncers.map((s) => s.idle()))
  void env
}

async function membership(sp, stats) {
  stats.membership++
  const candidates = sp.writers.filter((w) => w !== sp.authority)
  if (sp.removed.size && chance(0.5)) {
    const did = pick([...sp.removed])
    await putMember(sp.authority, sp.uri, did, true, true)
    sp.removed.delete(did)
    // writes made while removed were never tracked; the next one catches the authority up
    sp.repos.get(did).stale = true
  } else if (candidates.length > 1) {
    const w = pick(candidates)
    if (sp.removed.has(w.did)) return
    await attempt(() => sp.authority.client.com.atproto.memberspace.removeMember({ space: sp.uri, did: w.did }))
    sp.removed.add(w.did)
  }
}

function planFaults(total) {
  const plan = []
  const at = (frac) => Math.floor(total * frac)
  if (hostList.includes('vlpds')) {
    if (process.env.CLUSTER) {
      plan.push({ at: at(0.3), kind: 'kill9-node', node: 1, restartAfterMs: 20_000 })
      plan.push({ at: at(0.7), kind: 'sigterm-node', node: 2, restartAfterMs: 1000 })
    } else {
      plan.push({ at: at(0.33), kind: 'kill9', restartAfterMs: 500 })
      plan.push({ at: at(0.66), kind: 'sigterm', restartAfterMs: 500 })
    }
  }
  plan.push({ at: at(0.25), kind: 'syncer-restart' })
  plan.push({ at: at(0.5), kind: 'syncer-restart' })
  plan.push({ at: at(0.75), kind: 'syncer-restart-fresh' })
  return plan
}

const snapshots = new Map()
async function fire(f, world, env, stats) {
  stats.faultsFired.push(`${f.kind}@${f.at}`)
  log(`FAULT ${f.kind} at op ${f.at}`)
  if (f.kind === 'kill9' || f.kind === 'sigterm') {
    await env.vlpds.killNode(0, f.kind === 'kill9' ? 'SIGKILL' : 'SIGTERM')
    await sleep(f.restartAfterMs)
    await env.vlpds.restartNode(0)
  } else if (f.kind === 'kill9-node' || f.kind === 'sigterm-node') {
    await env.vlpds.killNode(f.node, f.kind === 'kill9-node' ? 'SIGKILL' : 'SIGTERM')
    await sleep(f.restartAfterMs)
    await env.vlpds.restartNode(f.node)
  } else if (f.kind.startsWith('syncer-restart')) {
    // a syncer process dies and comes back from its last persisted state (or none)
    const i = Math.floor(rand() * world.syncers.length)
    const old = world.syncers[i]
    await old.idle()
    const snap = f.kind === 'syncer-restart-fresh' ? undefined : (snapshots.get(old.name) ?? old.snapshot())
    const s = new Syncer(old.name, old.space, old.member, { snapshot: snap })
    s.svc = old.svc
    s.violations.push(...old.violations)
    for (const k of Object.keys(s.stats)) s.stats[k] += old.stats[k]
    old.notify = () => Promise.resolve() // the dead one hears nothing more
    world.syncers[i] = s
    env.svcs[old.svc].on((call) => {
      if (call.lxm === 'com.atproto.space.notifyWrite' && call.body.space === s.space) s.notify(call.body)
    })
    await s.sync()
  }
  for (const s of world.syncers) if (chance(0.3)) snapshots.set(s.name, s.snapshot())
}

async function invariants(world, env, check) {
  const { spaces, syncers } = world
  // resolve uncertain writes from each host's own listing; then I1
  for (const sp of spaces) {
    for (const repo of sp.repos.values()) {
      const own = await listOwn(repo.actor, sp.uri)
      const lost = []
      for (const [p, cid] of repo.truth) {
        if (cid === UNCERTAIN) {
          if (own.has(p)) repo.truth.set(p, own.get(p))
          else repo.truth.delete(p)
        } else if (own.get(p) !== cid) lost.push(`${p}: acked ${cid}, host has ${own.get(p)}`)
      }
      for (const [p, cid] of own) if (!repo.truth.has(p)) lost.push(`${p}: host has unacked ${cid}`)
      check(!lost.length, `I1 ${repo.actor} in space ${sp.n}: the host holds exactly the acked writes`, lost.slice(0, 5).join('; '))
    }
  }
  // I2: every active writer tracked at its head (outbox retries back off, so give it time)
  const deadline = Date.now() + Number(process.env.CONVERGE_MS ?? (FAULTS ? 240_000 : 30_000))
  for (const sp of spaces) {
    const reader = sp.reader
    for (;;) {
      const cred = await credentialFor(reader, sp.uri)
      const listed = await listReposAll(cred, sp.uri)
      const behind = []
      for (const w of sp.writers) {
        const rp = sp.repos.get(w.did)
        if (sp.removed.has(w.did) || rp.stale || !rp.acked) continue
        const head = await headOf(cred, sp.uri, w.did)
        const e = listed.find((x) => x.did === w.did)
        if (e?.repoRev !== head.rev) behind.push(`${w}: listed ${e?.repoRev} head ${head.rev}`)
      }
      if (!behind.length || Date.now() > deadline) {
        check(!behind.length, `I2 space ${sp.n}: the authority tracks every active writer at its head`, behind.join('; '))
        break
      }
      await sleep(2000)
    }
  }
  // I3 + I5: syncers catch up from their checkpoints and converge
  for (const s of syncers) s.lastError = null // errors while a host was down are expected; the final catch-up must not raise
  await Promise.all(syncers.map((s) => s.sync()))
  for (const s of syncers) {
    const sp = spaces.find((x) => x.uri === s.space)
    const cred = await credentialFor(sp.reader, sp.uri)
    const listed = await listReposAll(cred, sp.uri)
    if (s.lastError) check(false, `${s.name}: syncing raised`, s.lastError.message)
    const wrong = []
    for (const e of listed) {
      const local = s.repos.get(e.did)
      if (!local) {
        wrong.push(`${e.did} missing`)
        continue
      }
      const repo = sp.repos.get(e.did)
      if (!sp.removed.has(e.did) && repo && !repo.stale) {
        if (local.rev !== e.repoRev) wrong.push(`${e.did} at ${local.rev}, listed ${e.repoRev}`)
        const d = diff(repo.truth, s.view(e.did))
        if (d.length) wrong.push(`${e.did}: ${d.slice(0, 3).join(', ')}`)
        if (!hashEq(local.hash.digest(), e.data)) wrong.push(`${e.did}: LtHash differs from the listed data`)
      } else if (local.rev < e.repoRev) wrong.push(`${e.did} (removed) behind its listed repoRev`)
    }
    check(!wrong.length, `I3 ${s.name} converged on every listed repo`, wrong.slice(0, 5).join('; '))
    check(!s.violations.length, `I5 ${s.name}: no protocol violations`, s.violations.slice(0, 3).join('; '))
  }
  // I4: spaceRev bookkeeping across every forwarded notify each service received
  for (const [k, svc] of env.svcs.entries()) {
    const bySpace = new Map()
    for (const c of svc.callsTo('com.atproto.space.notifyWrite')) {
      if (!bySpace.has(c.body.space)) bySpace.set(c.body.space, [])
      bySpace.get(c.body.space).push(c.body)
    }
    for (const [space, calls] of bySpace) {
      const assigned = new Map()
      const prevOf = new Map()
      const bad = []
      for (const b of calls) {
        const key = `${b.repo} ${b.repoRev}`
        if (assigned.has(b.spaceRev) && assigned.get(b.spaceRev) !== key) bad.push(`spaceRev ${b.spaceRev} given to ${assigned.get(b.spaceRev)} and ${key}`)
        assigned.set(b.spaceRev, key)
        if (b.prevSpaceRev !== undefined) {
          if (prevOf.has(b.prevSpaceRev) && prevOf.get(b.prevSpaceRev) !== b.spaceRev) bad.push(`prevSpaceRev ${b.prevSpaceRev} forks to ${prevOf.get(b.prevSpaceRev)} and ${b.spaceRev}`)
          prevOf.set(b.prevSpaceRev, b.spaceRev)
          if (!(b.spaceRev > b.prevSpaceRev)) bad.push(`spaceRev ${b.spaceRev} not after its prev ${b.prevSpaceRev}`)
        }
      }
      const n = spaces.find((x) => x.uri === space)?.n
      check(!bad.length, `I4 service ${k}, space ${n}: ${calls.length} forwards, one spaceRev per update, no forks`, bad.slice(0, 3).join('; '))
    }
    check(!svc.authFailures.length, `service ${k}: every forward carried valid service auth`, svc.authFailures.slice(0, 2).map((c) => c.authErr).join('; '))
  }
}

async function listOwn(actor, space) {
  const out = new Map()
  let cursor
  do {
    const r = await actor.client.com.atproto.space.listRecords({ space, repo: actor.did, cursor, limit: 100 })
    for (const x of r.data.records) out.set(`${x.collection}/${x.rkey}`, String(x.cid))
    cursor = r.data.cursor
  } while (cursor)
  return out
}

async function listReposAll(cred, space) {
  const out = []
  let cursor
  const host = await cred.hostClient()
  for (;;) {
    const r = await host.com.atproto.space.listRepos({ space, cursor, limit: 100 })
    if (!r.data.repos.length) break
    for (const e of r.data.repos) {
      const i = out.findIndex((x) => x.did === e.did)
      if (i >= 0) out.splice(i, 1) // a repo can reappear when it moved during paging
      out.push(e)
    }
    cursor = r.data.cursor
  }
  return out
}

function diff(want, got) {
  const out = []
  for (const [k, v] of want) if (got?.get(k) !== v) out.push(`${k}: want ${v} got ${got?.get(k)}`)
  for (const [k, v] of got ?? []) if (!want.has(k)) out.push(`${k}: unexpected ${v}`)
  return out
}

/** Ack -> first forwarded notify for that (space, repo) after it, per service. */
function notifyLatencies(world, env, ackTimes) {
  if (!world) return []
  const out = []
  const svc = env.svcs[0]
  const byKey = new Map()
  for (const c of svc?.callsTo('com.atproto.space.notifyWrite') ?? []) {
    const k = `${c.body.space} ${c.body.repo}`
    if (!byKey.has(k)) byKey.set(k, [])
    byKey.get(k).push(c.at)
  }
  for (const a of ackTimes) {
    const arr = byKey.get(`${a.space} ${a.did}`)
    const t = arr?.find((x) => x >= a.t)
    if (t !== undefined) out.push(t - a.t)
  }
  return out
}

main().catch((e) => {
  console.error(e)
  process.exit(2)
})
