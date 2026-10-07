import { useSyncExternalStore } from 'react'
import { getNodeMetrics, type MetricsPoint, type NodeMetrics } from '../adminApi'
import { withAdmin } from './adminAdapter'
import { getLive, isUnsupported } from './live'

// The console's one getNodeMetrics poll. Every reader of per-node rates (Overview and Nodes
// through metrics.ts, the system pages through sys.ts, Limits' 429s through ratelimits.ts)
// subscribes here, so a tab makes one request per interval whatever is on screen. It runs only
// while something subscribes, skips ticks while the console is paused, and asks only for points
// newer than the ones it holds.

export const INTERVAL_MS = 2000
const KEEP_MS = 3 * 60_000

export type NodeSeries = {
  node: string
  self: boolean
  reachable: boolean
  /** Oldest first, the last 3 minutes. */
  series: MetricsPoint[]
  latest?: MetricsPoint | null
  /** The node's last answer (an unreachable node keeps its previous one): storeComponents, limits. */
  raw: NodeMetrics
}

export type NodeMetricsState = {
  status: 'pending' | 'ok' | 'unsupported' | 'error'
  nodes: NodeSeries[]
  unreachable: string[]
  error?: unknown
  /** Server time of the last answer. */
  time?: number
  at?: number
  version: number
}

let nm: NodeMetricsState = { status: 'pending', nodes: [], unreachable: [], version: 0 }
const subs = new Set<() => void>()
let timer: ReturnType<typeof setInterval> | undefined
let busy = false

async function tick(force = false) {
  if (busy || (!force && getLive().paused)) return
  busy = true
  try {
    const have = nm.nodes.filter((n) => n.series.length)
    // from the oldest node's newest point, so a lagging node isn't skipped
    const since = have.length && have.length === nm.nodes.length ? Math.min(...have.map((n) => n.series[n.series.length - 1].t)) : undefined
    const r = await withAdmin((c) => getNodeMetrics(c, since))
    const prev = new Map(nm.nodes.map((n) => [n.node, n]))
    const nodes: NodeSeries[] = r.nodes.map((n) => {
      const p = prev.get(n.node)
      const seen = new Set(p?.series.map((x) => x.t))
      const merged = [...(p?.series ?? []), ...(n.series ?? []).filter((x) => !seen.has(x.t))].filter((x) => x.t > r.time - KEEP_MS)
      return { node: n.node, self: n.self, reachable: n.reachable, series: merged, latest: n.latest ?? p?.latest, raw: n.reachable ? n : (p?.raw ?? n) }
    })
    nm = { status: 'ok', nodes, unreachable: r.unreachableNodes ?? [], time: r.time, at: Date.now(), version: nm.version + 1 }
  } catch (e) {
    nm = { ...nm, status: isUnsupported(e) ? 'unsupported' : nm.nodes.length ? nm.status : 'error', error: e, version: nm.version + 1 }
  } finally {
    busy = false
    subs.forEach((l) => l())
  }
}

/** Starts the poll with the first subscriber and stops it with the last. */
export function subscribeNodeMetrics(l: () => void) {
  subs.add(l)
  if (subs.size === 1) {
    tick(true)
    timer = setInterval(tick, INTERVAL_MS)
  }
  return () => {
    subs.delete(l)
    if (!subs.size && timer) {
      clearInterval(timer)
      timer = undefined
    }
  }
}

export const getNodeMetricsState = () => nm
export const refreshNodeMetrics = () => tick(true)

/** Every node's series and last answer, kept current while mounted. */
export const useNodeMetrics = () => useSyncExternalStore(subscribeNodeMetrics, getNodeMetricsState)
