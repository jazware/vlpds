import { clearLockout } from '../adminApi'
import { admin } from '../xrpc'
import { useMemo } from 'react'
import { withAdmin } from './adminAdapter'
import { K } from './keys'
import { mutate } from './mutate'
import { getNodeMetricsState, refreshNodeMetrics, useNodeMetrics, type NodeMetricsState } from './nodeMetrics'
import { shared, type Load } from './query'

// Rate limits and lockouts: getRateLimits (src/xrpc/ratelimits.rs) read with the 429 totals
// turned into per-bucket rates, the cluster's 429/s from getNodeMetrics, factor locks from
// listLockouts, and the edit model: every change is a small edit of the stored config, shown
// as a diff before updateRateLimits saves it.

export type KeyKind = 'ip' | 'identifier-ip' | 'did' | 'node' | 'cluster' | 'credential' | 'did-pair'
export type Limiter = {
  name: string
  key: KeyKind
  scope: string
  windowSecs: number
  points: number
  enabled: boolean
  custom: boolean
  default: { windowSecs: number; points: number } | null
}
export type ConfigError = { version: number | null; message: string; atMs: number }
export type RlNode = {
  node: string
  self: boolean
  reachable: boolean
  enabledByFlag?: boolean
  configVersion?: number
  configError?: ConfigError | null
  loadedAtMs?: number | null
  checkedAtMs?: number | null
  liveWindows?: number
}
export type Consumer = { key: string; used: number; maxNodeUsed: number; limit: number | null; resetMs: number; nodes: string[] }
export type Rejection = { limiter: string; route: string; last1m: number; last5m: number; last15m: number; total: number }
export type LimiterCfg = { enabled?: boolean; points?: number; windowSecs?: number }
export type RouteCfg = { nsid: string; points: number; windowSecs: number; enabled?: boolean }
export type OverrideCfg = { ip?: string; did?: string; limiters?: string[]; exempt?: boolean; points?: number; note?: string }
export type RlAudit = { version: number; at: string; by: string; ip?: string; node: string; note?: string; changes: string[] }
export type RlDoc = {
  version: number
  enabled?: boolean
  limiters?: Record<string, LimiterCfg>
  routes?: RouteCfg[]
  overrides?: OverrideCfg[]
  updatedAt?: string
  updatedBy?: string
  note?: string
  history?: RlAudit[]
}
export type RateLimits = {
  node: string
  enabledByFlag: boolean
  enabled: boolean
  configVersion: number
  config: RlDoc | null
  configError: ConfigError | null
  refreshSecs: number
  limiters: Limiter[]
  nodes: RlNode[]
  top: Record<string, Consumer[]>
  rejections: Rejection[]
  unreachableNodes?: string[]
  time: number
}

export const KEY_LABEL: Record<KeyKind, string> = {
  ip: 'client IP (IPv6: /64)',
  'identifier-ip': 'identifier + IP',
  did: 'DID',
  node: 'whole node',
  cluster: 'whole cluster (counted in the bucket)',
  credential: 'space credential (hash of issuer + jti)',
  'did-pair': 'account + space authority (hashed)',
}
export const KEY_SHORT: Record<KeyKind, string> = { ip: 'IP', 'identifier-ip': 'ID + IP', did: 'DID', node: 'node', cluster: 'cluster', credential: 'credential', 'did-pair': 'DID pair' }

export function fmtWindow(s: number): string {
  if (s % 86400 === 0) return s === 86400 ? '1 day' : `${s / 86400} days`
  if (s % 3600 === 0) return `${s / 3600} h`
  if (s % 60 === 0) return `${s / 60} min`
  return `${s} s`
}
export const fmtLimit = (points: number, windowSecs: number) => `${points.toLocaleString()} / ${fmtWindow(windowSecs)}`

/** Bucket names without the com.atproto. prefix every method bucket carries. */
export const shortName = (n: string) => n.replace(/^(route:)?com\.atproto\./, '$1')

/** What a bucket covers beyond the method its name already says ("" when nothing). */
export function scopeExtra(l: Limiter): string {
  const base = shortName(l.name).replace(/-\d+$/, '')
  if (l.scope === base) return ''
  if (l.scope.startsWith(`${base}; `)) return `also ${l.scope.slice(base.length + 2)}`
  return l.scope
}

// ---------------------------------------------------------------- getRateLimits + 429 history

const POLL = 5000
const KEEP = 72 // 6 minutes at 5 s
type Sample = { t: number; totals: Map<string, number> }
let samples: Sample[] = []

export type Loaded = RateLimits & { fetchedAt: number }

/** Every node's buckets, top keys and 429 totals; its busiest keys move by the second, so it polls as a series. */
export const rateLimitsQ = shared({
  key: K.ratelimits,
  fn: async (signal): Promise<Loaded> => {
    const d = await admin<RateLimits>('vlpds.admin.getRateLimits', { params: { top: 10 }, signal })
    const t = Date.now()
    const totals = new Map<string, number>()
    for (const r of d.rejections) totals.set(r.limiter, (totals.get(r.limiter) ?? 0) + r.total)
    samples = [...samples, { t: t / 1000, totals }].slice(-(KEEP + 1))
    history = undefined
    return { ...d, fetchedAt: t }
  },
  poll: POLL,
  stream: true,
  version: (d) => d.time,
})

export type History = { byBucket: Map<string, number[]>; total: number[]; samples: number; pollSecs: number }
let history: History | undefined

/** 429s per second per bucket since the console started polling (the change in each total between polls). */
export function rejectionHistory(): History {
  if (history) return history
  const byBucket = new Map<string, number[]>()
  const total: number[] = []
  const names = new Set<string>()
  for (const s of samples) for (const k of s.totals.keys()) names.add(k)
  for (const k of names) byBucket.set(k, [])
  for (let i = 1; i < samples.length; i++) {
    const a = samples[i - 1]
    const b = samples[i]
    const dt = b.t - a.t
    let sum = 0
    for (const k of names) {
      const v = dt > 0 ? Math.max(0, (b.totals.get(k) ?? 0) - (a.totals.get(k) ?? 0)) / dt : 0
      byBucket.get(k)!.push(v)
      sum += v
    }
    total.push(sum)
  }
  history = { byBucket, total, samples: total.length, pollSecs: POLL / 1000 }
  return history
}

/** The key closest to its limit (the limit applies to what one node counted). */
export function busiest(rows?: Consumer[]): Consumer | undefined {
  let best: Consumer | undefined
  let bf = -1
  for (const r of rows ?? []) {
    const f = r.limit ? r.maxNodeUsed / r.limit : -0.5
    if (f > bf) {
      best = r
      bf = f
    }
  }
  return best
}
export const held = (r: Consumer) => r.limit != null && r.maxNodeUsed >= r.limit

/** An identifier + IP key's two halves ("alice.example.com-203.0.113.9"). */
export function splitIdentKey(key: string): { ident: string; ip: string } {
  const i = key.lastIndexOf('-')
  return i < 0 ? { ident: key, ip: '' } : { ident: key.slice(0, i), ip: key.slice(i + 1) }
}

/** A key that can hold a sign-in: createSession's identifier + IP buckets, and DID buckets named for sign-in. */
export const isSignInBucket = (l: Pick<Limiter, 'name' | 'key'>) => l.key === 'identifier-ip' || (l.key === 'did' && /sign-in|createSession/.test(l.name))

export type HeldKey = { bucket: Limiter; c: Consumer; ident?: string; did?: string }

/** Sign-in keys at their limit now; `who` narrows them to one account's handle, email and DID. */
export function heldSignInKeys(d: RateLimits | undefined, who?: { did: string; handle?: string; email?: string | null }): HeldKey[] {
  if (!d) return []
  const names = who ? [who.handle, who.email, who.did].filter((x): x is string => !!x).map((x) => x.toLowerCase()) : []
  const out: HeldKey[] = []
  for (const b of d.limiters) {
    if (!b.enabled || !isSignInBucket(b)) continue
    for (const c of d.top[b.name] ?? []) {
      if (!held(c)) continue
      const k = b.key === 'identifier-ip' ? { ident: splitIdentKey(c.key).ident } : { did: c.key }
      if (who && !(k.did ? k.did === who.did : names.includes(k.ident!))) continue
      out.push({ bucket: b, c, ...k })
    }
  }
  return out
}

/** The override a key can get: a DID or an IP (an identifier+IP key's IP), or none. */
export function overrideTarget(kind: KeyKind, key: string): { ip?: string; did?: string } | undefined {
  if (kind === 'did' && key.startsWith('did:')) return { did: key }
  if (kind === 'ip') return { ip: key }
  if (kind === 'identifier-ip') {
    const ip = key.slice(key.lastIndexOf('-') + 1)
    return ip ? { ip } : undefined
  }
  return undefined
}

// ---------------------------------------------------------------- 429/s per node (getNodeMetrics)

export type RatePoint = { t: number; v: number }
export type Rate429 = { supported: boolean; nodes: { node: string; self: boolean; points: RatePoint[] }[]; intervalMs: number }

function rate429Of(s: NodeMetricsState): Load<Rate429> {
  const reload = () => void refreshNodeMetrics()
  if (s.status === 'pending') return { loading: true, reload }
  if (s.status === 'unsupported') return { data: { supported: false, nodes: [], intervalMs: 0 }, at: s.at, loading: false, reload }
  if (s.status === 'error') return { error: s.error, loading: false, reload }
  const nodes = s.nodes
    .filter((n) => n.series.length)
    .map((n) => ({ node: n.node, self: n.self, points: n.series.map((p) => ({ t: p.t, v: p.rateLimitedPerSec })) }))
    .sort((a, b) => a.node.localeCompare(b.node))
  const intervalMs = s.nodes.find((n) => n.raw.intervalMs)?.raw.intervalMs ?? 2000
  return { data: { supported: true, nodes, intervalMs }, at: s.at, loading: false, reload }
}

/** 429s per node per second, from the console's one getNodeMetrics query. */
export const rate429Q = {
  use: (): Load<Rate429> => {
    const s = useNodeMetrics()
    return useMemo(() => rate429Of(s), [s])
  },
  get: () => rate429Of(getNodeMetricsState()),
  refresh: () => refreshNodeMetrics(),
}

/** The cluster total, one point per interval (nodes' points bucketed to the interval). */
export function totalRate(r: Rate429 | undefined): number[] {
  if (!r?.nodes.length) return []
  const step = r.intervalMs || 2000
  const sum = new Map<number, number>()
  for (const n of r.nodes) for (const p of n.points) sum.set(Math.round(p.t / step), (sum.get(Math.round(p.t / step)) ?? 0) + p.v)
  return [...sum.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v)
}

// ---------------------------------------------------------------- factor locks (listLockouts: queries.ts lockoutsQ)

export const clearFactorLock = (did: string, reason: string) =>
  mutate({
    run: () => withAdmin((c) => clearLockout(c, { did, reason })),
    changes: [
      { kind: 'lockout', id: did },
      { kind: 'account', id: did },
    ],
  })

export const FACTOR_LABEL: Record<string, string> = { second_factor: 'TOTP and recovery codes', email_code: 'email codes' }

// ---------------------------------------------------------------- the edit model

/** The editable part of the config: every built-in bucket's values (defaults filled in), method buckets and overrides. */
export type Draft = {
  enabled: boolean
  limiters: Record<string, { points: number; windowSecs: number; enabled: boolean }>
  routes: RouteCfg[]
  overrides: OverrideCfg[]
}

export const builtins = (d: RateLimits) => d.limiters.filter((l) => !l.custom && l.default)

export function draftOf(d: RateLimits): Draft {
  const doc = d.config
  const limiters: Draft['limiters'] = {}
  for (const l of builtins(d)) {
    const c = doc?.limiters?.[l.name] ?? {}
    limiters[l.name] = { points: c.points ?? l.default!.points, windowSecs: c.windowSecs ?? l.default!.windowSecs, enabled: c.enabled ?? true }
  }
  return {
    enabled: doc?.enabled ?? true,
    limiters,
    routes: (doc?.routes ?? []).map((r) => ({ ...r, enabled: r.enabled ?? true })),
    overrides: doc?.overrides ?? [],
  }
}

/** The config object to save: only differences from the defaults. */
function docOf(draft: Draft, d: RateLimits): Omit<RlDoc, 'version'> {
  const limiters: Record<string, LimiterCfg> = {}
  for (const l of builtins(d)) {
    const v = draft.limiters[l.name]
    if (!v) continue
    const c: LimiterCfg = {}
    if (v.points !== l.default!.points) c.points = v.points
    if (v.windowSecs !== l.default!.windowSecs) c.windowSecs = v.windowSecs
    if (!v.enabled) c.enabled = false
    if (Object.keys(c).length) limiters[l.name] = c
  }
  return {
    enabled: draft.enabled,
    limiters,
    routes: draft.routes.map((r) => (r.enabled === false ? r : { nsid: r.nsid, points: r.points, windowSecs: r.windowSecs })),
    overrides: draft.overrides,
  }
}

/** The stored version an edit is made against (an object a node rejected still counts). */
export function baseVersion(d: RateLimits): number {
  let v = d.config?.version ?? 0
  for (const n of d.nodes) if (n.configError?.version != null) v = Math.max(v, n.configError.version)
  return v
}

export const overrideLabel = (o: OverrideCfg) =>
  `${o.ip ? `IP ${o.ip}` : `DID ${o.did}`} · ${o.limiters?.length ? o.limiters.map(shortName).join(', ') : 'all buckets'} · ${o.exempt ? 'exempt' : `${o.points?.toLocaleString()} points`}${o.note ? ` · “${o.note}”` : ''}`

/** One line per change between two drafts: [what, before, after]; before or after empty for added or removed. */
export function diffDrafts(a: Draft, b: Draft): [string, string, string][] {
  const out: [string, string, string][] = []
  const onoff = (v: boolean) => (v ? 'on' : 'off')
  if (a.enabled !== b.enabled) out.push(['Rate limiting', onoff(a.enabled), onoff(b.enabled)])
  for (const k of Object.keys(b.limiters)) {
    const x = a.limiters[k]
    const y = b.limiters[k]
    if (!x) continue
    if (x.points !== y.points || x.windowSecs !== y.windowSecs) out.push([shortName(k), fmtLimit(x.points, x.windowSecs), fmtLimit(y.points, y.windowSecs)])
    if (x.enabled !== y.enabled) out.push([shortName(k), onoff(x.enabled), onoff(y.enabled)])
  }
  for (const r of b.routes) {
    const o = a.routes.find((x) => x.nsid === r.nsid)
    const n = `route:${shortName(r.nsid)}`
    if (!o) out.push([n, '', `${fmtLimit(r.points, r.windowSecs)}${r.enabled === false ? ', off' : ''}`])
    else {
      if (o.points !== r.points || o.windowSecs !== r.windowSecs) out.push([n, fmtLimit(o.points, o.windowSecs), fmtLimit(r.points, r.windowSecs)])
      if ((o.enabled ?? true) !== (r.enabled ?? true)) out.push([n, onoff(o.enabled ?? true), onoff(r.enabled ?? true)])
    }
  }
  for (const r of a.routes) if (!b.routes.some((x) => x.nsid === r.nsid)) out.push([`route:${shortName(r.nsid)}`, fmtLimit(r.points, r.windowSecs), ''])
  const key = (o: OverrideCfg) => JSON.stringify(o)
  const ak = a.overrides.map(key)
  const bk = b.overrides.map(key)
  for (const o of a.overrides) if (!bk.includes(key(o))) out.push(['Override', overrideLabel(o), ''])
  for (const o of b.overrides) if (!ak.includes(key(o))) out.push(['Override', '', overrideLabel(o)])
  return out
}

export type SaveResult = { version: number; nodes: { node: string; ok: boolean; configVersion?: number; error?: string }[] }

export function saveDraft(d: RateLimits, draft: Draft, actor: string, note: string): Promise<SaveResult> {
  return mutate({
    run: () =>
      admin<SaveResult>('vlpds.admin.updateRateLimits', {
        body: { config: docOf(draft, d), ifVersion: baseVersion(d), actor: actor.trim() || undefined, note: note.trim() || undefined },
      }),
    changes: [{ kind: 'config', id: 'ratelimits' }],
  })
}

const ACTOR_KEY = 'vlpds.admin.actor'
export function lastActor(): string {
  try {
    return sessionStorage.getItem(ACTOR_KEY) ?? ''
  } catch {
    return ''
  }
}
export function rememberActor(a: string) {
  try {
    sessionStorage.setItem(ACTOR_KEY, a.trim())
  } catch {
    /* per-tab only */
  }
}

/** The current config, fresh: edits start from what the server has now. */
export const freshLimits = (): Promise<Loaded> => rateLimitsQ.fresh()
