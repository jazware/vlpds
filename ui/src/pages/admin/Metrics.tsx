import { useState } from 'react'
import { Banners, ErrorState, Loading, Mini, Minis, NeedsVersion, PageHead, Panel, PanelBody, Spark, Src, Swatch } from '../../components/console/kit'
import { toast } from '../../components/console/toast'
import { saveBlob } from '../../components/ui'
import { useClusterView } from '../../lib/console/cluster'
import { fmtBytes, fmtMs, fmtNum, fmtSi } from '../../lib/console/fmt'
import { nodeSeries, sumLatest, maxLatest, sumSeries, useNodeMetrics, worstSeries, type NodeSeries, type Num } from '../../lib/console/sys'
import { admin } from '../../lib/xrpc'

// Live metrics: every chart getNodeMetrics can draw, the cluster's line on top and each node's
// below it, over the 3 minutes each node keeps. History and alerts are Grafana's.

type Chart = {
  title: string
  sub: string
  k: Num
  l2?: Num
  /** Rates add up across nodes; latencies and levels show the worst node. */
  agg: 'sum' | 'max'
  fmt: (v: number | undefined) => string
  color: string
  th?: number
}

const si = (v?: number) => (v === undefined ? '—' : fmtSi(v))
const bytesPerSec = (v?: number) => (v === undefined ? '—' : `${fmtBytes(v)}/s`)
const bytes = (v?: number) => (v === undefined ? '—' : fmtBytes(v))
const cores = (v?: number) => (v === undefined ? '—' : `${v.toFixed(2)} cores`)
const ms = (v?: number) => fmtMs(v)

const CHARTS: Chart[] = [
  { title: 'Commits / s', sub: 'ops/s dashed: more ops than commits means writes coalesce', k: 'commitsPerSec', l2: 'opsPerSec', agg: 'sum', fmt: si, color: 'accent' },
  { title: 'Commit → durable', sub: 'p99, p50 dashed · enqueue until the segment is durable and acked', k: 'commitP99Ms', l2: 'commitP50Ms', agg: 'max', fmt: ms, color: 'amber', th: 500 },
  { title: 'Segment PUT', sub: 'p99, p50 dashed · hedges and retries included', k: 'putP99Ms', l2: 'putP50Ms', agg: 'max', fmt: ms, color: 'amber' },
  { title: 'HTTP requests / s', sub: '5xx dashed', k: 'httpPerSec', l2: 'http5xxPerSec', agg: 'sum', fmt: si, color: 'c2' },
  { title: 'Rate-limited / s', sub: '429s answered', k: 'rateLimitedPerSec', agg: 'sum', fmt: si, color: 'warn' },
  { title: 'Firehose events / s', sub: 'emitted by each node: every node sends the whole stream', k: 'firehoseEventsPerSec', agg: 'max', fmt: si, color: 'accent' },
  { title: 'Firehose sent', sub: 'bytes to subscribers', k: 'firehoseBytesPerSec', agg: 'sum', fmt: bytesPerSec, color: 'c2' },
  { title: 'Firehose emit delay', sub: 'p99 · alert at 2 s', k: 'emitP99Ms', agg: 'max', fmt: ms, color: 'violet', th: 2000 },
  { title: 'Cold repo loads / s', sub: 'repos rebuilt from state', k: 'repoLoadsPerSec', agg: 'sum', fmt: si, color: 'c6' },
  { title: 'Object store, class A / s', sub: 'PUT · LIST · CAS; class B dashed', k: 'classAPerSec', l2: 'classBPerSec', agg: 'sum', fmt: si, color: 'c3' },
  { title: 'Object-store errors / s', sub: 'timeouts and errors after retries', k: 'storeErrorsPerSec', agg: 'sum', fmt: si, color: 'err' },
  { title: 'CPU', sub: 'cores busy', k: 'cpuCores', agg: 'sum', fmt: cores, color: 'c6' },
  { title: 'Memory', sub: 'resident', k: 'rssBytes', agg: 'sum', fmt: bytes, color: 'c4' },
  { title: 'Repos in memory', sub: 'cached across workers', k: 'cachedRepos', agg: 'sum', fmt: (v) => (v === undefined ? '—' : fmtNum(v)), color: 'c5' },
  { title: 'Firehose subscribers', sub: 'connections', k: 'subscribers', agg: 'sum', fmt: (v) => (v === undefined ? '—' : fmtNum(v)), color: 'c1' },
]

function ChartPanel({ c, nodes, color }: { c: Chart; nodes: NodeSeries[]; color: (n: string) => string | undefined }) {
  const agg = c.agg === 'sum' ? sumSeries : worstSeries
  const now = c.agg === 'sum' ? sumLatest(nodes, c.k) : maxLatest(nodes, c.k)
  return (
    <Panel title={c.title} right={<b className="mono">{c.fmt(now)}</b>}>
      <PanelBody>
        <div className="muted sm" style={{ marginBottom: 6 }}>
          {c.sub}
          {nodes.length > 1 ? ` · ${c.agg === 'sum' ? 'all nodes' : 'worst node'}` : ''}
        </div>
        <Spark size="big" data={agg(nodes, c.k)} l2={c.l2 ? agg(nodes, c.l2) : undefined} color={c.color} th={c.th} title={c.title} />
      </PanelBody>
      {nodes.length > 1 && (
        <Minis n={Math.min(3, nodes.length)}>
          {nodes.map((n) => (
            <Mini
              key={n.node}
              label={
                <>
                  <Swatch color={color(n.node)} /> {n.node.replace(/^vlpds-/, '')}
                </>
              }
              value={c.fmt(n.latest?.[c.k] ?? undefined)}
            >
              <Spark data={nodeSeries(n, c.k)} l2={c.l2 ? nodeSeries(n, c.l2) : undefined} color={c.color} th={c.th} />
            </Mini>
          ))}
        </Minis>
      )}
    </Panel>
  )
}

export function Metrics() {
  const m = useNodeMetrics()
  const { view } = useClusterView()
  const [busy, setBusy] = useState(false)
  const color = (n: string) => view?.nodes.find((x) => x.node === n)?.color
  const dl = async (name: string, file: string) => {
    setBusy(true)
    try {
      const r: Response = await admin('vlpds.admin.getGrafanaDashboard', { params: { name }, raw: true })
      saveBlob(await r.blob(), file)
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), { err: true })
    } finally {
      setBusy(false)
    }
  }
  const head = (
    <PageHead
      title="Live metrics"
      sub={
        <>
          <span>every node, one point per 2 s, the last 3 minutes</span>
          <span>history and alerts live in Grafana</span>
        </>
      }
      actions={
        <>
          <button type="button" className="cx-btn" disabled={busy} onClick={() => dl('vlpds', 'vlpds.json')} title="Grafana: Dashboards → New → Import">
            vlpds.json
          </button>
          <button type="button" className="cx-btn" disabled={busy} onClick={() => dl('internals', 'vlpds-internals.json')} title="Grafana: Dashboards → New → Import">
            vlpds-internals.json
          </button>
        </>
      }
    />
  )
  if (m.status === 'unsupported')
    return (
      <>
        {head}
        <Panel>
          <NeedsVersion what="Live metrics" nsid="vlpds.admin.getNodeMetrics" />
        </Panel>
      </>
    )
  if (m.status === 'pending') return <Loading label="Asking every node…" />
  if (!m.nodes.length) return <ErrorState error={m.error} />
  const nodes = m.nodes.filter((n) => n.reachable)
  return (
    <>
      {head}
      <Banners items={m.unreachable.length ? [{ id: 'u', tone: 'warn', title: `${m.unreachable.join(', ')} didn't answer`, desc: 'Their lines are missing.' }] : []} />
      <div className="cx-grid3">
        {CHARTS.map((c) => (
          <ChartPanel key={c.title} c={c} nodes={nodes} color={color} />
        ))}
      </div>
      <p className="muted sm">
        <Src>vlpds.admin.getNodeMetrics · 2 s</Src> The dashboard buttons download what <span className="mono">vlpds dashboards</span> prints, for Grafana’s Import dialog.
      </p>
    </>
  )
}
