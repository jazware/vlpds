import { segmentFeed, type Segment } from './adminAdapter'
import { createPoller } from './live'

// vlpds.admin.listSegments every 2 s for the strata canvas: each node's sealed segments, kept for
// 20 s by log. A poll asks from just before the previous answer, or from the oldest segment
// still in flight, so a PUT that finishes later turns its block solid.

const KEEP_MS = 20_000

export type SegmentLanes = {
  /** Server time of the last answer. */
  time: number
  /** By log id, oldest first. */
  logs: Record<string, Segment[]>
}

let lanes: SegmentLanes | undefined
let unsupported: string | undefined

async function fetchSegments(): Promise<{ supported: boolean; nsid?: string; lanes?: SegmentLanes }> {
  if (unsupported) return { supported: false, nsid: unsupported }
  let since: number | undefined
  if (lanes) {
    since = lanes.time - 2_500
    for (const segs of Object.values(lanes.logs)) for (const s of segs) if (s.durableAt == null && s.sealedAt < since) since = s.sealedAt
  }
  const r = await segmentFeed(since)
  if (!r.supported) {
    unsupported = r.nsid
    return { supported: false, nsid: r.nsid }
  }
  const logs: Record<string, Segment[]> = { ...(lanes?.logs ?? {}) }
  for (const n of r.data.nodes) {
    if (!n.reachable || !n.log) continue
    const byOrd = new Map((logs[n.log] ?? []).map((s) => [s.ordinal, s]))
    for (const s of n.segments ?? []) byOrd.set(s.ordinal, s)
    logs[n.log] = [...byOrd.values()].filter((s) => s.sealedAt >= r.data.time - KEEP_MS).sort((a, b) => a.ordinal - b.ordinal)
  }
  lanes = { time: r.data.time, logs }
  return { supported: true, lanes }
}

export const segmentsPoll = createPoller(fetchSegments, 2000)
