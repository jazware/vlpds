import { useMemo } from 'react'
import { seqMillis } from '../format'
import { admin } from '../xrpc'
import { K } from './keys'
import { shared } from './query'

// vlpds.admin.getClusterStatus, read every 2 s while any console page shows it (and at once when
// the change feed says leases, owners or the layout changed). It is the console's heartbeat: when
// it fails the shell says "not updating".

export type ClusterNode = {
  node: string
  log: string
  addr: string
  writer: number
  expiresMs: number
  self: boolean
  reachable: boolean
  leaseValid?: boolean
  logDurableOrdinal?: number | null
  owned?: number
  rev?: string
  minLevel?: number
  maxLevel?: number
  seenLevel?: number
}

export type FeatureLevels = {
  active: number | null
  target: number | null
  history: { level: number; at: string; by: string }[]
  binary: { min: number; max: number; rev: string }
  mixedBuilds: boolean
  revs: string[]
  finalizable: number | null
  finalizedAt: string | null
  error?: string
}

export type ClusterStatus = {
  node: string
  publicUrl?: string
  log: string
  logDurableOrdinal: number | null
  owned: number[]
  shards: number
  table: (string | null)[]
  nodes: ClusterNode[]
  leaseValid: boolean
  leaseExpiresMs?: number
  firehose: { lastEmitted: string; minWatermark: string | null; sources: { log: string; watermark: string; local: boolean }[] }
  fencedLogs: Record<string, number>
  time: number
  version?: FeatureLevels
  /** Shards in slot order (table[i] owns layout.shards[i]); absent on a single node. */
  layout?: { version: number; shards: { id: number; lo: number; hi: number }[]; op?: unknown }
}

/** One poll's view of every log, kept for the strata canvas (ordinal deltas become segments). */
export type LogSample = { t: number; logs: Record<string, { ordinal?: number; wmMs?: number }> }
const HISTORY_MS = 20_000
const history: LogSample[] = []
export const logHistory = () => history

async function fetchCluster(signal?: AbortSignal): Promise<ClusterStatus & { fetchedAt: number }> {
  const c: ClusterStatus = await admin('vlpds.admin.getClusterStatus', { signal })
  const logs: LogSample['logs'] = {}
  for (const s of c.firehose.sources) logs[s.log] = { wmMs: seqMillis(s.watermark) }
  for (const n of c.nodes) logs[n.log] = { ...logs[n.log], ordinal: n.logDurableOrdinal ?? undefined }
  if (!c.nodes.length) logs[c.log] = { ...logs[c.log], ordinal: c.logDurableOrdinal ?? undefined }
  history.push({ t: c.time, logs })
  while (history.length && history[0].t < c.time - HISTORY_MS) history.shift()
  return { ...c, fetchedAt: Date.now() }
}

export const clusterQ = shared({ key: K.cluster, fn: fetchCluster, poll: 2000, stream: true, version: (c) => c.time })
export const useCluster = clusterQ.use

const SLOTS = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6']

/** A node's color, fixed by its place among the sorted node ids (so it keeps it while it lives). */
export function nodeColor(ids: string[], id: string | null | undefined): string | undefined {
  if (!id) return undefined
  const i = ids.indexOf(id)
  if (i < 0) return 'var(--ink3)'
  if (ids.length <= SLOTS.length) return `var(--${SLOTS[i]})`
  const hue = Math.round(160 + (i * 360) / ids.length) % 360
  return `oklch(${i % 2 ? 0.6 : 0.74} 0.13 ${hue})`
}

export type NodeView = ClusterNode & {
  color?: string
  shards: number
  /** How far this log's firehose watermark trails the server clock, ms. */
  wmLagMs?: number
  /** This log holds the merged firehose back. */
  slowest: boolean
  /** ms until the lease runs out (negative: expired). */
  leaseLeftMs?: number
  health: 'ok' | 'warn' | 'err'
}

export type ClusterView = {
  raw: ClusterStatus
  /** Running without a cluster (--memory, one process): no leases, every shard local. */
  single: boolean
  self: string
  ids: string[]
  nodes: NodeView[]
  table: (string | null)[]
  unowned: number
  leased: number
  wmLagMs?: number
  lastEmittedMs?: number
}

/** The status with what every page derives from it: colors, shard counts, watermark lag. */
export function clusterView(c: ClusterStatus): ClusterView {
  const single = !c.node
  const self = c.node || (c.publicUrl ? new URL(c.publicUrl).host : 'this node')
  const nodes0: ClusterNode[] = single
    ? [{ node: self, log: c.log, addr: c.publicUrl ?? '', writer: 0, expiresMs: 0, self: true, reachable: true, leaseValid: true, logDurableOrdinal: c.logDurableOrdinal, owned: c.shards }]
    : c.nodes
  const table = single ? Array.from({ length: c.shards }, () => self) : c.table
  const ids = [...new Set([...nodes0.map((n) => n.node), ...(table.filter(Boolean) as string[])])].sort()
  const counts = new Map<string, number>()
  for (const o of table) if (o) counts.set(o, (counts.get(o) ?? 0) + 1)
  const wm = new Map(c.firehose.sources.map((s) => [s.log, s.watermark]))
  const nodes = nodes0.map((n): NodeView => {
    const w = seqMillis(wm.get(n.log))
    const leaseLeftMs = single ? undefined : n.expiresMs - c.time
    const health = !n.reachable ? 'err' : !single && n.leaseValid === false ? 'err' : leaseLeftMs !== undefined && leaseLeftMs < 3000 ? 'warn' : 'ok'
    return {
      ...n,
      color: nodeColor(ids, n.node),
      shards: n.owned ?? counts.get(n.node) ?? 0,
      wmLagMs: w !== undefined ? Math.max(0, c.time - w) : undefined,
      slowest: c.firehose.sources.length > 1 && !!c.firehose.minWatermark && wm.get(n.log) === c.firehose.minWatermark,
      leaseLeftMs,
      health,
    }
  })
  const minWm = seqMillis(c.firehose.minWatermark)
  return {
    raw: c,
    single,
    self,
    ids,
    nodes,
    table,
    unowned: table.filter((o) => !o).length,
    leased: single ? 1 : nodes.filter((n) => n.leaseValid && n.reachable).length,
    wmLagMs: minWm !== undefined ? Math.max(0, c.time - minWm) : undefined,
    lastEmittedMs: seqMillis(c.firehose.lastEmitted),
  }
}

export function useClusterView(): { view?: ClusterView; error?: unknown; loading: boolean; at?: number } {
  const p = useCluster()
  const view = useMemo(() => (p.data ? clusterView(p.data) : undefined), [p.data])
  return { view, error: p.error, loading: p.loading, at: p.at }
}
