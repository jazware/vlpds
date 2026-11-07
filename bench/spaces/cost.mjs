// Sync cost (README.md): what steady polling and notify-driven pulls cost
// the server, measured against the Spaces targets.
//
//   node cost.mjs [host] [step,...]   host: vlpds (default with VLPDS_BIN) | ref-a (client-side numbers only)
//                                     steps: noop-poll delta-pull notify-latency bucket-ops
//                                     public-p99-under-space-load warm-writes (default: all)
//
// Server time per call comes from vlpds_http_request_duration_seconds
// (sum/count deltas, and quantiles from the bucket deltas); bucket ops from
// vlpds_object_store_requests_total and MinIO's own request counters, net of
// the idle rate. Targets: no-op listRepoOps well under 1 ms server time, a
// delta pull a few ms, zero added bucket ops per space write (compared with a
// public write), notify without linger, public commit p99 unaffected by a
// space write load.
import { Actor, RUN } from './lib/actor.mjs'
import { COLL, PORTS, URLS, log } from './lib/env.mjs'
import { attempt, setTimingScope, sleep } from './lib/http.mjs'
import { NotifyService } from './lib/notifysvc.mjs'
import { Report, pct, summarize } from './lib/report.mjs'
import { createSpace, credentialFor, putMember } from './lib/space.mjs'
import { Vlpds } from './lib/vlpds.mjs'

const host = process.argv[2] ?? (process.env.VLPDS_BIN ? 'vlpds' : 'ref-a')
const only = process.argv[3] ? new Set(process.argv[3].split(',')) : null
const N = Number(process.env.COST_N ?? 300)
const WARM_N = Number(process.env.WARM_N ?? 210)
const rep = new Report(process.env.REPORT ?? (only ? `cost-${host}-${[...only].join('+')}` : `cost-${host}`), {
  run: RUN,
  host,
  n: N,
  vlpds: process.env.VLPDS_REV ?? '(none)',
  cluster: !!process.env.CLUSTER,
  steps: only ? [...only] : 'all',
})
const cfg = host

/** A cost step: skipped unless selected, and its calls timed under its own scope. */
const step = (name, fn, opts = {}) => {
  setTimingScope(`${cfg} ${name}`)
  return rep.step(cfg, name, fn, name !== 'setup' && only && !only.has(name) ? { skip: 'not selected' } : opts)
}

const env = {}

async function metrics() {
  return env.vlpds ? env.vlpds.metrics() : new Map()
}

async function minio() {
  const r = await fetch(`${URLS.minio}/minio/v2/metrics/cluster`).catch(() => null)
  const m = new Map()
  if (!r?.ok) return m
  for (const line of (await r.text()).split('\n')) {
    const x = /^minio_s3_requests_total\{([^}]*)\} (\S+)/.exec(line)
    if (x) {
      const api = /api="([^"]+)"/.exec(x[1])?.[1] ?? '?'
      m.set(api, (m.get(api) ?? 0) + Number(x[2]))
    }
  }
  return m
}

function delta(a, b, pred) {
  let s = 0
  for (const [k, v] of b) if (pred(k)) s += v - (a.get(k) ?? 0)
  return s
}

/**
 * A histogram's delta between two snapshots, over the series `labels` selects
 * (a substring of the label set): count, mean, and upper bucket bounds for
 * p50/p90/p99, in ms.
 */
function hist(a, b, name, labels = '') {
  const sel = (suffix) => (k) => k.startsWith(`${name}_${suffix}`) && k.includes(labels)
  const count = delta(a, b, sel('count'))
  if (!count) return null
  const sum = delta(a, b, sel('sum'))
  const buckets = new Map()
  for (const [k, v] of b) {
    if (!sel('bucket')(k)) continue
    const raw = /le="([^"]+)"/.exec(k)[1]
    const le = raw === '+Inf' ? Infinity : Number(raw)
    buckets.set(le, (buckets.get(le) ?? 0) + v - (a.get(k) ?? 0))
  }
  const sorted = [...buckets].sort((x, y) => x[0] - y[0])
  const q = (p) => +(sorted.find(([, c]) => c >= p * count)?.[0] * 1000).toFixed(3)
  return { count, mean_ms: +((sum / count) * 1000).toFixed(4), p50_le_ms: q(0.5), p90_le_ms: q(0.9), p99_le_ms: q(0.99) }
}

/** Server-side time of one XRPC method between two snapshots. */
const serverTime = (a, b, method) => hist(a, b, 'vlpds_http_request_duration_seconds', `method="${method}"`)

const storeOps = (a, b) => delta(a, b, (k) => k.startsWith('vlpds_object_store_requests_total{'))
const storeOpsBy = (a, b) => {
  const out = {}
  for (const [k, v] of b) {
    if (!k.startsWith('vlpds_object_store_requests_total{')) continue
    const d = v - (a.get(k) ?? 0)
    if (!d) continue
    const key = `${/op="([^"]+)"/.exec(k)?.[1]}/${/component="([^"]+)"/.exec(k)?.[1]}`
    out[key] = (out[key] ?? 0) + d
  }
  return out
}

async function timed(fn) {
  const t0 = performance.now()
  await fn()
  return performance.now() - t0
}

async function pool(n, conc, fn) {
  let i = 0
  const lat = []
  await Promise.all(
    Array.from({ length: conc }, async () => {
      while (i < n) {
        const k = i++
        lat.push(await timed(() => fn(k)))
      }
    }),
  )
  return lat
}

async function main() {
  env.svc = await new NotifyService(PORTS.syncer).start()
  if (host === 'vlpds') env.vlpds = await new Vlpds({ cluster: !!process.env.CLUSTER }).start()
  const S = {}
  try {
    await step('setup', async (check) => {
      S.A = await Actor.create(host, 'ca')
      S.W = await Actor.create(host, 'cw')
      S.R = await Actor.create(host, 'cr')
      S.space = await createSpace(S.A, `cost${RUN}`)
      await putMember(S.A, S.space, S.W, true, true)
      await putMember(S.A, S.space, S.R, true, false)
      for (let i = 0; i < 50; i++) await S.W.client.com.atproto.space.createRecord({ space: S.space, repo: S.W.did, collection: COLL, rkey: `seed${i}`, record: rec(i) })
      S.cred = await credentialFor(S.R, S.space)
      S.wc = await S.cred.macClient(S.W.did)
      await (await S.cred.hostClient()).com.atproto.space.registerNotify({ space: S.space, service: env.svc.serviceRef })
      check(true, 'space with a writer (50 records) and a registered syncer')
    })

    await step('noop-poll', async (check) => {
      const head = (await S.wc.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W.did })).data.commit.rev
      for (let i = 0; i < 20; i++) await S.wc.com.atproto.space.listRepoOps({ space: S.space, repo: S.W.did, since: head })
      const m0 = await metrics()
      const lat = []
      for (let i = 0; i < N; i++) lat.push(await timed(() => S.wc.com.atproto.space.listRepoOps({ space: S.space, repo: S.W.did, since: head })))
      const m1 = await metrics()
      const st = serverTime(m0, m1, 'com.atproto.space.listRepoOps')
      rep.metrics.noop_poll = { client_ms: summarize(lat), server: st, bucket_ops: env.vlpds ? storeOps(m0, m1) : null }
      if (st) {
        check(st.mean_ms < 1, `no-op listRepoOps server mean ${st.mean_ms} ms < 1 ms`, JSON.stringify(st))
        check(storeOps(m0, m1) === 0, `no-op polls touch the bucket 0 times (${storeOps(m0, m1)})`, JSON.stringify(storeOpsBy(m0, m1)))
      } else rep.note(`${cfg}: no server-side timing (client p50 ${pct(lat, 50)} ms)`)
    }, { needs: ['setup'] })

    await step('delta-pull', async (check) => {
      let since = (await S.wc.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W.did })).data.commit.rev
      const m0 = await metrics()
      const lat = []
      for (let i = 0; i < Math.min(N, 200); i++) {
        await S.W.client.com.atproto.space.putRecord({ space: S.space, repo: S.W.did, collection: COLL, rkey: `d${i % 10}`, record: rec(i) })
        let res
        lat.push(await timed(async () => (res = await S.wc.com.atproto.space.listRepoOps({ space: S.space, repo: S.W.did, since }))))
        if (!res.data.ops.length) check(false, 'a delta pull returns the new op')
        since = res.data.commit?.rev ?? since
      }
      const m1 = await metrics()
      const st = serverTime(m0, m1, 'com.atproto.space.listRepoOps')
      rep.metrics.delta_pull = { client_ms: summarize(lat), server: st }
      if (st) check(st.mean_ms < 5, `delta pull server mean ${st.mean_ms} ms < 5 ms`, JSON.stringify(st))
    }, { needs: ['setup'] })

    await step('notify-latency', async (check) => {
      const lat = []
      const before = env.svc.calls.length
      for (let i = 0; i < Math.min(N, 200); i++) {
        await S.W.client.com.atproto.space.putRecord({ space: S.space, repo: S.W.did, collection: COLL, rkey: `n${i % 10}`, record: rec(i) })
        const t = performance.now()
        const rev = (await S.wc.com.atproto.space.getLatestCommit({ space: S.space, repo: S.W.did })).data.commit.rev
        for (let k = 0; k < 200; k++) {
          const c = env.svc.calls.slice(before).find((x) => x.body?.repoRev === rev && x.body?.repo === S.W.did)
          if (c) {
            lat.push(c.at - t)
            break
          }
          await sleep(5)
        }
        await sleep(100)
      }
      rep.metrics.notify = summarize(lat)
      check(lat.length > 0.95 * Math.min(N, 200), `forwarded notifies arrived (${lat.length})`)
      check(pct(lat, 50) < 100, `notify p50 ${pct(lat, 50)} ms after the write is readable (no linger)`)
    }, { needs: ['setup'] })

    await step('bucket-ops', async (check) => {
      if (!env.vlpds) return rep.note(`${cfg}: bucket ops only measured on vlpds`)
      const idle0 = await metrics()
      const mi0 = await minio()
      await sleep(10_000)
      const idle1 = await metrics()
      const mi1 = await minio()
      const idleRate = storeOps(idle0, idle1) / 10
      const run = async (label, fn) => {
        const a = await metrics()
        const ma = await minio()
        const t0 = Date.now()
        await pool(N, 4, fn)
        await sleep(2000)
        const b = await metrics()
        const mb = await minio()
        const secs = (Date.now() - t0) / 1000
        const ops = storeOps(a, b) - idleRate * secs
        const mops = delta(ma, mb, () => true) - (delta(mi0, mi1, () => true) / 10) * secs
        return { label, writes: N, vlpds_ops_per_write: +(ops / N).toFixed(3), minio_ops_per_write: +(mops / N).toFixed(3), by_op: storeOpsBy(a, b) }
      }
      const pub = await run('public', (i) => S.W.client.com.atproto.repo.createRecord({ repo: S.W.did, collection: 'com.example.publicThing', record: { $type: 'com.example.publicThing', i, createdAt: new Date().toISOString() } }))
      const spc = await run('space', (i) => S.W.client.com.atproto.space.createRecord({ space: S.space, repo: S.W.did, collection: COLL, record: rec(i) }))
      rep.metrics.bucket_ops = { idle_per_s: idleRate, public: pub, space: spc }
      check(spc.vlpds_ops_per_write <= pub.vlpds_ops_per_write + 0.05, `space write bucket ops/write ${spc.vlpds_ops_per_write} <= public ${pub.vlpds_ops_per_write} (no added ops)`, JSON.stringify(spc.by_op))
    }, { needs: ['setup'] })

    await step('public-p99-under-space-load', async (check) => {
      const pubWrite = (i) => S.W.client.com.atproto.repo.createRecord({ repo: S.W.did, collection: 'com.example.publicThing', record: { $type: 'com.example.publicThing', i, createdAt: new Date().toISOString() } })
      const alone = await pool(N, 4, pubWrite)
      let stop = false
      const X = await Actor.create(host, 'cx')
      await putMember(S.A, S.space, X, true, true)
      const bg = Promise.all(
        Array.from({ length: 8 }, async () => {
          let i = 0
          while (!stop) await X.client.com.atproto.space.createRecord({ space: S.space, repo: X.did, collection: COLL, record: rec(i++) }).catch(() => {})
        }),
      )
      const loaded = await pool(N, 4, pubWrite)
      stop = true
      await bg
      rep.metrics.public_commit_ms = { alone: summarize(alone), with_space_load: summarize(loaded) }
      const a = pct(alone, 99)
      const b = pct(loaded, 99)
      check(b <= a * 1.25 + 2, `public commit p99 ${b} ms under space load vs ${a} ms alone (within 25% + 2 ms)`)
    }, { needs: ['setup'] })

    await step('warm-writes', async (check) => {
      // its own account and space, so it doesn't need setup's members: the
      // owner writes into its own space; if the host won't let it (no
      // putMember yet, say), a member of a space on ref-a writes instead
      const W = await Actor.create(host, 'cwarm')
      let space = await createSpace(W, `warm${RUN}`)
      const probe = await attempt(() => W.client.com.atproto.space.createRecord({ space, repo: W.did, collection: COLL, record: rec(-1) })).catch((e) => ({ ok: false, error: e.message }))
      if (!probe.ok) {
        if (host === 'ref-a') throw new Error(`owner write refused: ${probe.error}`)
        const A = await Actor.create('ref-a', 'cwarma')
        space = await createSpace(A, `warm${RUN}`)
        await putMember(A, space, W, true, true)
        rep.note(`warm-writes: the owner's write on ${host} was refused (${probe.error}); writing as a member of a ref-a space`)
      }
      rep.meta.warm_space = space
      const c = W.client.com.atproto.space
      const base = { space, repo: W.did }
      const methods = {
        createRecord: (i) => c.createRecord({ ...base, collection: COLL, record: rec(i) }),
        putRecord: (i) => c.putRecord({ ...base, collection: COLL, rkey: `w${i % 20}`, record: rec(i) }),
        applyWrites: (i) => c.applyWrites({ ...base, writes: [{ $type: 'com.atproto.space.applyWrites#create', collection: COLL, value: rec(i) }] }),
      }
      for (let i = 0; i < 30; i++) for (const fn of Object.values(methods)) await fn(i)
      const m0 = await metrics()
      const lat = Object.fromEntries(Object.keys(methods).map((k) => [k, []]))
      const t0 = performance.now()
      for (let i = 0; i < WARM_N; i++) for (const [k, fn] of Object.entries(methods)) lat[k].push(await timed(() => fn(i)))
      const wall = performance.now() - t0
      const m1 = await metrics()
      const out = { rounds: WARM_N, writes_per_s: +((3 * WARM_N) / (wall / 1000)).toFixed(1), client_ms: {} }
      for (const [k, v] of Object.entries(lat)) out.client_ms[k] = summarize(v)
      if (env.vlpds) {
        out.server_http = Object.fromEntries(Object.keys(methods).map((k) => [k, serverTime(m0, m1, `com.atproto.space.${k}`)]))
        // per segment, not per write: a segment can carry several commits
        out.commit_stage = Object.fromEntries(
          ['seal_wait', 'put', 'apply_lock', 'apply', 'ack'].map((st) => [st, hist(m0, m1, 'vlpds_commit_stage_seconds', `stage="${st}"`)]),
        )
        out.commit_durable = hist(m0, m1, 'vlpds_commit_durable_seconds')
        out.space_writes = {}
        for (const [k, v] of m1) {
          if (!k.startsWith('vlpds_space_writes_total{')) continue
          const d = v - (m0.get(k) ?? 0)
          if (d) out.space_writes[`${/op="([^"]+)"/.exec(k)?.[1]}/${/result="([^"]+)"/.exec(k)?.[1]}`] = d
        }
        out.bucket_ops_per_write = +(storeOps(m0, m1) / (3 * WARM_N)).toFixed(3)
      }
      rep.metrics.warm_writes = out
      const ms = (x) => (x == null ? '' : x)
      const tbl = [
        `${WARM_N} rounds of createRecord, putRecord and a one-op applyWrites, in turn, by one account in one space after 30 warmup rounds; ${out.writes_per_s} writes/s.`,
        '',
        '| method | client p50 | p90 | p99 | max | server mean | server p50 ≤ | p99 ≤ |',
        '|---|---|---|---|---|---|---|---|',
        ...Object.entries(out.client_ms).map(([k, v]) => {
          const sv = out.server_http?.[k]
          return `| ${k} | ${v.p50} | ${v.p90} | ${v.p99} | ${v.max} | ${ms(sv?.mean_ms)} | ${ms(sv?.p50_le_ms)} | ${ms(sv?.p99_le_ms)} |`
        }),
      ]
      if (out.commit_stage) {
        tbl.push('', '| commit stage (per segment) | count | mean | p50 ≤ | p90 ≤ | p99 ≤ |', '|---|---|---|---|---|---|')
        for (const [k, v] of [...Object.entries(out.commit_stage), ['commit_durable', out.commit_durable]]) {
          tbl.push(v ? `| ${k} | ${v.count} | ${v.mean_ms} | ${v.p50_le_ms} | ${v.p90_le_ms} | ${v.p99_le_ms} |` : `| ${k} | 0 | | | | |`)
        }
        tbl.push('', `space writes ${JSON.stringify(out.space_writes)}; bucket ops/write ${out.bucket_ops_per_write}`)
      }
      rep.section(`Warm write latency on ${host} (ms)`, tbl)
      for (const [k, v] of Object.entries(lat)) check(v.length === WARM_N, `${k}: ${WARM_N} sequential writes acked (p50 ${pct(v, 50)} ms, p99 ${pct(v, 99)} ms)`)
    })
  } finally {
    log(`report: ${rep.write()}`)
    await env.svc.stop()
    if (env.vlpds && process.env.KEEP !== '1') await env.vlpds.stop()
  }
  console.log(`\n${rep.markdown()}`)
  process.exit(rep.failed().length ? 1 : 0)
}

const rec = (i) => ({ $type: COLL, text: `cost ${i}`, createdAt: new Date().toISOString() })

main().catch((e) => {
  console.error(e)
  process.exit(2)
})
