import { getConfig, getStorageStats, listMail, type MetricsPoint, type NodeConfig, type StorageStats } from '../adminApi'
import { admin, basic, getAdminToken, setAdminToken, XrpcError } from '../xrpc'
import { clusterPoll, type ClusterStatus } from './cluster'
import { withAdmin } from './adminAdapter'
import { createPoller, isUnsupported } from './live'
import { subscribersPoll, type Subscriber, type SubscriberList } from './polls'

// Data for the system sections (Firehose & relays, Object store, Mail, Config, Spaces): the
// typed console API (lib/adminApi.ts) plus the older admin calls these pages share.

/** An older vlpds without the method. */
export const missing = isUnsupported

// ---------------------------------------------------------------- node metrics

// one shared poll (nodeMetrics.ts): series 3 minutes deep, one point per 2 s
export { useNodeMetrics, type NodeMetricsState, type NodeSeries } from './nodeMetrics'
import type { NodeSeries } from './nodeMetrics'

export type Num = Exclude<
  { [K in keyof MetricsPoint]: MetricsPoint[K] extends number ? K : MetricsPoint[K] extends number | null | undefined ? K : never }[keyof MetricsPoint],
  undefined
>

/** A field over time, summed across nodes by interval (rates add up; latencies don't, use `worst`). */
export function sumSeries(nodes: NodeSeries[], k: Num): (number | null)[] {
  return aligned(nodes, k, (xs) => xs.reduce((a, b) => a + b, 0))
}
export function worstSeries(nodes: NodeSeries[], k: Num): (number | null)[] {
  return aligned(nodes, k, (xs) => Math.max(...xs))
}
function aligned(nodes: NodeSeries[], k: Num, f: (xs: number[]) => number): (number | null)[] {
  const step = 2000
  const live = nodes.filter((n) => n.series.length)
  if (!live.length) return []
  const end = Math.max(...live.map((n) => n.series[n.series.length - 1].t))
  const slots = 90
  const out: (number | null)[] = []
  for (let i = slots - 1; i >= 0; i--) {
    const hi = end - i * step
    const xs: number[] = []
    for (const n of live) {
      const p = n.series.find((x) => x.t > hi - step && x.t <= hi)
      const v = p?.[k]
      if (typeof v === 'number' && isFinite(v)) xs.push(v)
    }
    out.push(xs.length ? f(xs) : null)
  }
  // drop leading gaps from before the console opened
  const first = out.findIndex((v) => v != null)
  return first < 0 ? [] : out.slice(first)
}
export const nodeSeries = (n: NodeSeries | undefined, k: Num) => (n?.series ?? []).map((p) => (p[k] as number | null | undefined) ?? null)

/** The last-10-s figure summed over nodes. */
export function sumLatest(nodes: NodeSeries[], k: Num): number | undefined {
  const xs = nodes.map((n) => n.latest?.[k]).filter((v): v is number => typeof v === 'number')
  return xs.length ? xs.reduce((a, b) => a + b, 0) : undefined
}
export function maxLatest(nodes: NodeSeries[], k: Num): number | undefined {
  const xs = nodes.map((n) => n.latest?.[k]).filter((v): v is number => typeof v === 'number')
  return xs.length ? Math.max(...xs) : undefined
}

// ---------------------------------------------------------------- firehose: per-connection rates

export type SubRates = {
  /** Per `node/conn`: events per second between the last two polls, oldest first. */
  conns: Map<string, number[]>
  /** The PDS's own event rate (any one node: every node emits the merged stream). */
  pds: number[]
  /** Bytes per second to all subscribers. */
  sent: number[]
  version: number
}
const KEEP_POLLS = 36 // 3 minutes at 5 s
let sr: SubRates = { conns: new Map(), pds: [], sent: [], version: 0 }
let lastList: (SubscriberList & { at: number }) | undefined
export const subKey = (s: Pick<Subscriber, 'node' | 'conn'>) => `${s.node}/${s.conn}`

/** Feeds a fresh listFirehoseSubscribers answer into the rate history. */
export function noteSubscribers(d: SubscriberList | undefined) {
  if (!d || lastList?.time === d.time) return
  const p = lastList
  lastList = { ...d, at: d.time }
  if (!p) return
  const secs = (d.time - p.time) / 1000
  if (secs <= 0) return
  const before = new Map(p.subscribers.map((s) => [subKey(s), s]))
  const conns = new Map<string, number[]>()
  for (const s of d.subscribers) {
    const k = subKey(s)
    const b = before.get(k)
    const v = b ? Math.max(0, s.events - b.events) / secs : null
    const hist = sr.conns.get(k) ?? []
    conns.set(k, v == null ? hist : [...hist, v].slice(-KEEP_POLLS))
  }
  let pds: number | undefined
  let sent: number | undefined
  const pn = new Map(p.nodes.map((n) => [n.node, n]))
  for (const n of d.nodes) {
    const b = pn.get(n.node)
    if (!n.reachable || !b?.reachable || n.eventsEmitted == null || b.eventsEmitted == null) continue
    pds = Math.max(pds ?? 0, Math.max(0, n.eventsEmitted - b.eventsEmitted) / secs)
    if (n.bytesSent != null && b.bytesSent != null) sent = (sent ?? 0) + Math.max(0, n.bytesSent - b.bytesSent) / secs
  }
  sr = {
    conns,
    pds: pds === undefined ? sr.pds : [...sr.pds, pds].slice(-KEEP_POLLS),
    sent: sent === undefined ? sr.sent : [...sr.sent, sent].slice(-KEEP_POLLS),
    version: sr.version + 1,
  }
}

/** listFirehoseSubscribers every 5 s plus the rates worked out from consecutive answers. */
export function useSubRates() {
  const subs = subscribersPoll.use()
  noteSubscribers(subs.data)
  return { subs, rates: sr }
}

// ---------------------------------------------------------------- relays

export type RelayStatus = { lastAttemptMs: number; lastSuccessMs?: number; ok: boolean; httpStatus?: number; error?: string; node: string }
export type Relay = { relay: string; url: string; status?: RelayStatus }
export type Crawlers = {
  hostname: string
  relays: Relay[]
  intervalSecs: number
  relaysSource: 'stored' | 'flags'
  intervalSource: 'stored' | 'flags'
  flagRelays: string[]
  flagIntervalSecs: number
  updatedAt?: string
  node: string
  sender: boolean
}
export type CrawlResult = { relay: string; ok: boolean; status?: number; error?: string }
export const crawlersPoll = createPoller(() => admin<Crawlers>('vlpds.admin.getCrawlers'), 10_000)
export const setCrawlers = (body: { relays?: string[] | null; intervalSecs?: number | null }) => admin('vlpds.admin.setCrawlers', { body })
export const requestCrawl = (relays: string[]) => admin<{ results: CrawlResult[] }>('vlpds.admin.requestCrawl', { body: { relays } })

// ---------------------------------------------------------------- mail

export const mailPoll = createPoller(() => withAdmin((c) => listMail(c, 200)), 5000)

/** The rate-limit buckets the mailer spends (getRateLimits): the cluster's daily budget and each node's hourly one. */
export type MailBudget = {
  limiter: string
  points: number
  windowSecs: number
  enabled: boolean
  /** The busiest keys: the cluster, the node bucket (`used` summed, `maxNodeUsed` the busiest node's), or recipients. */
  top: { key: string; used: number; maxNodeUsed: number; nodes: string[]; resetMs: number }[]
}
type RL = {
  enabled: boolean
  limiters: { name: string; windowSecs: number; points: number; enabled: boolean; scope: string }[]
  top: Record<string, { key: string; used: number; maxNodeUsed: number; limit: number | null; resetMs: number; nodes: string[] }[]>
}
export const mailBudgetPoll = createPoller(async (): Promise<{ enabled: boolean; budgets: MailBudget[] }> => {
  const r = await admin<RL>('vlpds.admin.getRateLimits')
  const budgets = r.limiters
    .filter((l) => l.name.startsWith('mail-'))
    .map((l) => ({ limiter: l.name, points: l.points, windowSecs: l.windowSecs, enabled: l.enabled, top: r.top[l.name] ?? [] }))
  return { enabled: r.enabled, budgets }
}, 15_000)

// ---------------------------------------------------------------- per node

/** Every node holding a lease (or this one alone), for calls each node answers for itself. */
async function leasedNodes() {
  const c = clusterPoll.get().data ?? (await admin<ClusterStatus>('vlpds.admin.getClusterStatus'))
  return c.nodes.length ? c.nodes.map((n) => ({ node: n.node, self: n.self })) : [{ node: c.node, self: true }]
}

/** An admin GET answered by one node (the `x-vlpds-node` relay over peer mTLS); no node: this one. */
export async function adminAt<T>(nsid: string, node: string | undefined, params?: Record<string, string>): Promise<T> {
  const token = getAdminToken()
  if (!token) throw new XrpcError(401, 'AuthenticationRequired', 'Enter the admin token')
  const q = params ? `?${new URLSearchParams(params)}` : ''
  const r = await fetch(`/xrpc/${nsid}${q}`, { headers: { authorization: basic(token), ...(node ? { 'x-vlpds-node': node } : {}) } })
  const body = await r.json().catch(() => ({}))
  if (!r.ok) {
    if (r.status === 401) setAdminToken(null)
    throw new XrpcError(r.status, body.error ?? `HTTP ${r.status}`, body.message ?? '')
  }
  return body as T
}

// ---------------------------------------------------------------- spaces

export type SpacesStatus = {
  node?: string | null
  outbox: { rows: number; max: number }
  fanout: { pending: number; queueMax: number }
  revocations: { entries: number; hardCap: number; blockedSpaces: number; blockedAuthorities: number; saturated: boolean; loaded: boolean; fresh: boolean; refreshEverySecs: number; staleAfterSecs: number }
  credentialCache: { entries: number; max: number }
}
/** getSpacesStatus from every node. */
export const spacesStatusPoll = createPoller(
  async () =>
    Promise.all(
      (await leasedNodes()).map(async ({ node, self }): Promise<{ node: string; status?: SpacesStatus; error?: unknown }> => {
        try {
          return { node, status: await adminAt<SpacesStatus>('vlpds.admin.getSpacesStatus', self ? undefined : node) }
        } catch (error) {
          return { node, error }
        }
      }),
    ),
  10_000,
)

// ---------------------------------------------------------------- config

export type NodeConfigResult = { node: string; self: boolean; config?: NodeConfig; error?: unknown }

/** getConfig from every node holding a lease (relayed over peer mTLS). A node that fails keeps its error. */
export async function configs(): Promise<NodeConfigResult[]> {
  const nodes = await leasedNodes()
  return Promise.all(
    nodes.map(async ({ node, self }) => {
      try {
        return { node, self, config: await withAdmin((cl) => getConfig(cl, self ? undefined : node)) }
      } catch (error) {
        return { node, self, error }
      }
    }),
  )
}
export const configPoll = createPoller(configs, 30_000)

// ---------------------------------------------------------------- storage stats

export type { StorageStats } from '../adminApi'

/** Objects and bytes per key component; `supported: false` on a vlpds without getStorageStats. */
export const storageStatsPoll = createPoller(async (): Promise<{ supported: false } | { supported: true; data: StorageStats }> => {
  try {
    return { supported: true, data: await withAdmin((c) => getStorageStats(c)) }
  } catch (e) {
    if (isUnsupported(e)) return { supported: false }
    throw e
  }
}, 60_000)
