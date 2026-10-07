import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import { getNodeMetrics, type MetricsPoint, type NodeMetrics } from '../adminApi'
import { withAdmin } from './adminAdapter'
import { K } from './keys'
import { isUnsupported } from './live'
import { observe, options, queryClient, type QueryDef } from './query'

// The console's one getNodeMetrics query. Every reader of per-node rates (Overview and Nodes
// through metrics.ts, the system pages through sys.ts, Limits' 429s through ratelimits.ts) reads
// it, so a tab makes one request per interval whatever is on screen. It runs only while
// something reads it, stops with the rest when the console is paused, and asks only for points
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
}

type Held = { nodes: NodeSeries[]; unreachable: string[]; time: number; unsupported?: boolean }

/** The next answer merged onto the points already held. */
async function fetchMetrics(signal: AbortSignal): Promise<Held> {
  const prevHeld = queryClient.getQueryData<Held>(K.nodeMetrics)
  const prevNodes = prevHeld?.nodes ?? []
  const have = prevNodes.filter((n) => n.series.length)
  // from the oldest node's newest point, so a lagging node isn't skipped
  const since = have.length && have.length === prevNodes.length ? Math.min(...have.map((n) => n.series[n.series.length - 1].t)) : undefined
  let r
  try {
    r = await withAdmin((c) => getNodeMetrics(c, since, signal))
  } catch (e) {
    if (isUnsupported(e)) return { nodes: [], unreachable: [], time: Date.now(), unsupported: true }
    throw e
  }
  const prev = new Map(prevNodes.map((n) => [n.node, n]))
  const nodes: NodeSeries[] = r.nodes.map((n) => {
    const p = prev.get(n.node)
    const seen = new Set(p?.series.map((x) => x.t))
    const merged = [...(p?.series ?? []), ...(n.series ?? []).filter((x) => !seen.has(x.t))].filter((x) => x.t > r.time - KEEP_MS)
    return { node: n.node, self: n.self, reachable: n.reachable, series: merged, latest: n.latest ?? p?.latest, raw: n.reachable ? n : (p?.raw ?? n) }
  })
  return { nodes, unreachable: r.unreachableNodes ?? [], time: r.time }
}

const def: QueryDef<Held> = { key: K.nodeMetrics, fn: fetchMetrics, poll: INTERVAL_MS, stream: true, version: (h) => h.time }

function stateOf(q: { data?: Held; error: unknown; dataUpdatedAt: number }): NodeMetricsState {
  const d = q.data
  if (d?.unsupported) return { status: 'unsupported', nodes: [], unreachable: [], at: q.dataUpdatedAt }
  if (!d) return { status: q.error ? 'error' : 'pending', nodes: [], unreachable: [], error: q.error ?? undefined }
  return { status: 'ok', nodes: d.nodes, unreachable: d.unreachable, time: d.time, at: q.dataUpdatedAt, error: q.error ?? undefined }
}

/** Every node's series and last answer, kept current while mounted. */
export function useNodeMetrics(): NodeMetricsState {
  const q = useQuery(options(def))
  return useMemo(() => stateOf(q), [q.data, q.error, q.dataUpdatedAt])
}

/** For stores outside React (metrics.ts): fetched and polled while `l` is subscribed. */
export const subscribeNodeMetrics = (l: () => void) => observe(def, l)

export function getNodeMetricsState(): NodeMetricsState {
  const st = queryClient.getQueryState<Held>(K.nodeMetrics)
  return stateOf({ data: st?.data, error: st?.error ?? null, dataUpdatedAt: st?.dataUpdatedAt ?? 0 })
}

export const refreshNodeMetrics = () => queryClient.invalidateQueries({ queryKey: K.nodeMetrics })

/** When each node's process started (unix ms), from the same query. */
export function useStartedAt(): Map<string, number> {
  const s = useNodeMetrics()
  return useMemo(() => new Map(s.nodes.filter((n) => n.raw.startedAt).map((n) => [n.node, n.raw.startedAt!])), [s])
}
