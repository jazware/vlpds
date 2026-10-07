import { useEffect, useRef } from 'react'
import { logHistory, type ClusterView } from '../../lib/console/cluster'
import { getLive } from '../../lib/console/live'
import { segmentsPoll } from '../../lib/console/segments'

// "Logs → watermark → firehose": one lane per node's log over the last 15 s. Each block is a
// log segment (a batch of commits written with one PUT), placed where it was sealed, sized by
// its events and outlined until its PUT is durable (listSegments). The amber ticks are each
// log's watermark and the dashed line the slowest one, which the merged firehose emits up to.
// A server without listSegments gets blocks from the durable ordinal advancing between two
// getClusterStatus polls, spread over the interval.

const SPAN = 15_000
const LANE = 30

type Seg = { start: number; log: string; events?: number; inflight?: boolean }

function segmentsFrom(): { segs: Seg[]; latest?: number } {
  const h = logHistory()
  const feed = segmentsPoll.get().data?.lanes
  if (feed) {
    const segs: Seg[] = []
    for (const [log, list] of Object.entries(feed.logs))
      for (const s of list) segs.push({ log, start: s.sealedAt, events: s.events, inflight: s.durableAt == null })
    return { segs, latest: h[h.length - 1]?.t ?? feed.time }
  }
  const segs: Seg[] = []
  for (let i = 1; i < h.length; i++) {
    const a = h[i - 1]
    const b = h[i]
    for (const [log, cur] of Object.entries(b.logs)) {
      const was = a.logs[log]?.ordinal
      if (cur.ordinal === undefined || was === undefined || cur.ordinal <= was) continue
      const k = Math.min(cur.ordinal - was, 24)
      for (let j = 0; j < k; j++) segs.push({ log, start: a.t + ((j + 0.5) * (b.t - a.t)) / k })
    }
  }
  return { segs, latest: h[h.length - 1]?.t }
}

export function Strata({ view, fetchedAt }: { view: ClusterView; fetchedAt?: number }) {
  // keeps the feed polling while the canvas is up; the draw loop reads it with get()
  segmentsPoll.use()
  const ref = useRef<HTMLCanvasElement>(null)
  const viewRef = useRef(view)
  viewRef.current = view
  const atRef = useRef(fetchedAt)
  atRef.current = fetchedAt
  const lanes = view.nodes.length
  const H = lanes * LANE + 26

  useEffect(() => {
    const c = ref.current
    if (!c) return
    let raf = 0
    let last = 0
    let col: Record<string, string> = {}
    let colAt = 0
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
    const draw = (ts: number) => {
      raf = requestAnimationFrame(draw)
      const live = getLive()
      if (ts - last < (reduce ? 1000 : 66) || ((live.paused || live.stale) && last)) return
      last = ts
      if (ts - colAt > 1000) {
        const cs = getComputedStyle(c)
        col = Object.fromEntries(['ink2', 'ink3', 'rule2', 'amber', 'err', 'sunk', 'idle'].map((k) => [k, cs.getPropertyValue(`--${k}`).trim()]))
        colAt = ts
      }
      const v = viewRef.current
      const W = c.clientWidth
      if (!W) return
      const dpr = window.devicePixelRatio || 1
      if (c.width !== Math.round(W * dpr) || c.height !== Math.round(H * dpr)) {
        c.width = Math.round(W * dpr)
        c.height = Math.round(H * dpr)
      }
      const g = c.getContext('2d')!
      g.setTransform(dpr, 0, 0, dpr, 0, 0)
      g.clearRect(0, 0, W, H)
      const { segs, latest } = segmentsFrom()
      // server clock now: the last status's time plus what passed since it arrived
      const t = (latest ?? v.raw.time) + (atRef.current ? Date.now() - atRef.current : 0)
      const narrow = W < 520
      const x0 = narrow ? 70 : 128
      const x1 = W - 6
      const X = (ms: number) => x1 - ((t - ms) / SPAN) * (x1 - x0)
      const lane = (i: number) => 8 + i * LANE
      const minWm = v.wmLagMs !== undefined ? v.raw.time - v.wmLagMs : undefined
      g.font = '500 10px "JetBrains Mono", monospace'
      g.textBaseline = 'middle'
      g.strokeStyle = col.rule2
      g.lineWidth = 1
      for (let s = 0; s <= 15; s += 5) {
        const x = Math.round(X(t - s * 1000)) + 0.5
        g.beginPath()
        g.moveTo(x, 4)
        g.lineTo(x, H - 18)
        g.stroke()
        g.fillStyle = col.ink3
        g.textAlign = s === 0 ? 'right' : 'center'
        g.fillText(s === 0 ? 'now' : `−${s} s`, x, H - 8)
      }
      v.nodes.forEach((n, i) => {
        const y = lane(i)
        const bad = n.health === 'err'
        g.textAlign = 'left'
        g.fillStyle = bad ? col.err : col.ink2
        g.font = '600 11px "JetBrains Mono", monospace'
        g.fillText(narrow ? n.node.replace(/^vlpds-/, '') : n.node, 0, y + 7, x0 - 8)
        if (!narrow) {
          g.font = '400 9.5px "JetBrains Mono", monospace'
          g.fillStyle = bad ? col.err : col.ink3
          g.fillText(bad ? (n.reachable ? 'lease expired' : 'unreachable') : n.log, 0, y + 19, x0 - 8)
        }
        g.fillStyle = col.sunk
        g.fillRect(x0, y + 1, x1 - x0, 22)
        const color = n.color ? (n.color.startsWith('var(') ? getComputedStyle(c).getPropertyValue(n.color.slice(4, -1)).trim() : n.color) : col.idle
        const mine = segs.filter((s) => s.log === n.log)
        // a busy log draws thinner blocks so they stay apart
        const gap = mine.length > 1 ? (x1 - x0) / ((SPAN / 1000) * (mine.length / ((mine[mine.length - 1].start - mine[0].start) / 1000 || 1))) : 8
        const bw = Math.max(1.5, Math.min(6, gap * 0.6))
        for (const s of mine) {
          const x = X(s.start)
          if (x < x0 || x > x1) continue
          const w = s.events !== undefined ? Math.max(1.5, Math.min(bw, 3 + s.events * 0.8)) : bw
          if (s.inflight) {
            g.strokeStyle = col.ink3
            g.setLineDash([2, 2])
            g.strokeRect(x + 0.5, y + 5.5, w, 13)
            g.setLineDash([])
            continue
          }
          g.globalAlpha = minWm === undefined || s.start <= minWm ? 1 : 0.45
          g.fillStyle = bad ? col.idle : color
          g.fillRect(x, y + 5, w, 14)
          g.globalAlpha = 1
        }
        if (n.wmLagMs !== undefined) {
          const wx = X(v.raw.time - n.wmLagMs)
          if (wx > x0) {
            g.fillStyle = col.amber
            g.fillRect(Math.round(wx) - 1, y + 1, 2, 4)
            g.fillRect(Math.round(wx) - 1, y + 19, 2, 4)
          }
        }
      })
      if (minWm !== undefined) {
        const wx = X(minWm)
        if (wx > x0) {
          g.strokeStyle = col.amber
          g.lineWidth = 1.5
          g.setLineDash([4, 3])
          g.beginPath()
          g.moveTo(Math.round(wx) + 0.5, 4)
          g.lineTo(Math.round(wx) + 0.5, lane(lanes - 1) + 26)
          g.stroke()
          g.setLineDash([])
        }
      }
    }
    raf = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(raf)
  }, [H, lanes])

  return <canvas ref={ref} style={{ height: H }} aria-label="Each node's log segments over the last 15 seconds, and the firehose watermark" role="img" />
}
