import type { ReactNode } from 'react'
import { Chip, Copy, KV, Meter, Mini, Minis, Spark, Src, Tiles } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import { Strata } from '../../components/console/Strata'
import type { ClusterView, NodeView } from '../../lib/console/cluster'
import { ago, dur, fmtBytes, fmtMs, fmtNum, fmtPct, fmtSec, fmtSi, plural } from '../../lib/console/fmt'
import { col, last, nodeGauges, nodePoints, type MetricsState } from '../../lib/console/metrics'
import type { SubscriberList } from '../../lib/console/queries'
import { segmentsQ } from '../../lib/console/segments'
import { useNodeMetrics } from '../../lib/console/sys'
import { finalizeLevel, LeaseCell, ShardMap } from './clusterUi'

// Nodes & shards on a cluster of one: a single panel for the node, its rates and its log,
// instead of cards, a shard map and tables that would each repeat the same node.

export function OneNode({ view, n, m, subs, at }: { view: ClusterView; n: NodeView; m: MetricsState; subs?: SubscriberList; at?: number }) {
  const nm = useNodeMetrics()
  const feed = segmentsQ.use().data?.supported
  const raw = nm.nodes.find((x) => x.node === n.node)?.raw
  const p = nodePoints(m, n.node, n.self)
  const g = nodeGauges(m, n.node, n.self)
  const v = view.raw.version
  const fh = view.raw.firehose
  const fenced = Object.entries(view.raw.fencedLogs)
  const here = subs?.subscribers.filter((s) => s.node === n.node).length
  const memLimit = g?.memLimit ?? raw?.memoryLimitBytes
  const memFrac = g?.resident !== undefined && memLimit ? g.resident / memLimit : undefined
  const tone = n.color?.match(/--(c\d)/)?.[1] ?? 'accent'
  const mini = (label: ReactNode, value: string, data: (number | null)[], color: string, l2?: (number | null)[]) => (
    <Mini label={label} value={value}>
      <Spark data={data} l2={l2} color={color} />
    </Mini>
  )
  return (
    <section className="cx-pn cx-solo">
      <div className="cx-pn-h">
        <span className="cx-sw" style={{ background: n.color }} />
        <h3 className="cx-solo-name mono">{n.node}</h3>
        {n.self && <Chip k="acc">this node</Chip>}
        <LeaseCell n={n} single={view.single} />
        <div className="r">
          {n.rev && (
            <span className="mono sm t2" title={n.rev}>
              {n.rev.slice(0, 12)}
            </span>
          )}
          {n.addr && <Copy text={n.addr.replace(/^https?:\/\//, '')} />}
          <button type="button" className="cx-btn sm" onClick={() => openPanel('node', n.node)}>
            Node details
          </button>
        </div>
      </div>
      <Tiles
        tiles={[
          { label: 'commits/s', value: p ? fmtSi(last(p, 'commits') ?? NaN) : '—', sec: p && last(p, 'ops') !== undefined ? `${fmtSi(last(p, 'ops')!)} ops/s` : undefined },
          { label: 'commit → durable', right: 'p99', value: p ? fmtSec(last(p, 'durP99')) : '—' },
          { label: 'segment PUT', right: 'p99', value: p ? fmtSec(last(p, 'putP99')) : '—' },
          { label: 'CPU', right: raw?.cpuLimitCores ? `of ${raw.cpuLimitCores} cores` : undefined, value: p ? fmtPct(last(p, 'cpu')) : '—' },
          {
            label: 'memory',
            right: memLimit ? `of ${fmtBytes(memLimit)}` : undefined,
            value: g?.resident !== undefined ? fmtBytes(g.resident) : '—',
            spark: memFrac !== undefined ? <Meter v={g!.resident!} max={memLimit!} k={memFrac > 0.85 ? 'warn' : 'ok'} wide /> : undefined,
          },
          { label: 'shards', right: 'owned', value: `${fmtNum(n.shards)}`, sec: `of ${fmtNum(view.table.length)}` },
          { label: 'watermark lag', value: fmtMs(n.wmLagMs) },
          { label: 'subscribers', right: 'firehose', value: here ?? g?.subscribers ?? '—' },
        ]}
      />
      {p ? (
        <Minis n={4} style={{ borderTop: '1px solid var(--rule2)', paddingTop: 10 }}>
          {mini('commits/s', fmtSi(last(p, 'commits') ?? NaN), col(p, 'commits'), tone)}
          {mini('commit → durable p99 · p50', fmtSec(last(p, 'durP99')), col(p, 'durP99'), 'amber', col(p, 'durP50'))}
          {mini('segment PUT p99 · p50', fmtSec(last(p, 'putP99')), col(p, 'putP99'), 'violet', col(p, 'putP50'))}
          {mini('CPU', fmtPct(last(p, 'cpu')), col(p, 'cpu'), 'c6')}
          {mini('requests/s · 5xx', fmtSi(last(p, 'http') ?? NaN), col(p, 'http'), 'c2', col(p, 'http5xx'))}
          {mini('firehose events/s', fmtSi(last(p, 'fhEvents') ?? NaN), col(p, 'fhEvents'), 'accent')}
          {mini('object store A · B req/s', fmtSi((last(p, 'objA') ?? 0) + (last(p, 'objB') ?? 0)), col(p, 'objA'), 'c3', col(p, 'objB'))}
          {mini('429s/s', fmtSi(last(p, 'limited') ?? NaN), col(p, 'limited'), 'warn')}
        </Minis>
      ) : (
        <div className="cx-pn-b muted sm">No metrics for this node{m.source === 'local' ? '' : ': this server has no vlpds.admin.getNodeMetrics and no /metrics on the app port'}.</div>
      )}
      <div className="cx-solo-strata">
        <div className="cx-eyebrow">
          Log segments, last 15 s <Src>{feed ? 'listSegments' : 'getClusterStatus · durable ordinal'}</Src>
        </div>
        <div className="cx-strata">
          <Strata view={view} fetchedAt={at} />
        </div>
      </div>
      <div className="cx-solo-cols">
        <div>
          <div className="cx-eyebrow">
            Log and firehose <Src>getClusterStatus</Src>
          </div>
          <KV
            rows={[
              ['Log', <Copy text={n.log} />],
              ['Durable ordinal', <span className="mono">{n.logDurableOrdinal != null ? fmtNum(n.logDurableOrdinal) : 'no segments yet'}</span>],
              ['Writer byte', <span className="mono">{n.writer}</span>],
              ['Last emitted', fh.lastEmitted !== '0' ? <Copy text={fh.lastEmitted} /> : '—'],
              ['Watermark', view.wmLagMs !== undefined ? `${fmtMs(view.wmLagMs)} behind now` : '—'],
              ['Sources', `${plural(fh.sources.length, 'log')} (${fh.sources.filter((s) => s.local).length} local)`],
              ...(fenced.length ? [['Fenced', fenced.map(([l, end]) => <div key={l} className="mono sm">{l}@{end}</div>)] as [string, ReactNode]] : []),
            ]}
          />
        </div>
        <div>
          <div className="cx-eyebrow">
            Shards {view.raw.layout && <span className="muted">· layout v{view.raw.layout.version}</span>}
          </div>
          <ShardMap view={view} only={n.node} />
        </div>
        <div>
          <div className="cx-eyebrow">
            Build and feature level <Src>cluster/version</Src>
          </div>
          <KV
            rows={[
              ['Revision', n.rev ? <Copy text={n.rev} /> : '—'],
              ['Can run levels', n.minLevel != null ? `${n.minLevel}–${n.maxLevel}` : '—'],
              [
                'Active level',
                v ? (
                  <>
                    {v.active ?? '—'}
                    {v.finalizedAt && <span className="muted"> · finalized {ago(Date.parse(v.finalizedAt))}</span>}
                  </>
                ) : (
                  '—'
                ),
                v?.finalizable != null && v.target == null
                  ? {
                      act: (
                        <button type="button" className="cx-btn sm" onClick={() => finalizeLevel(v.finalizable!, view)}>
                          Finalize {v.finalizable}…
                        </button>
                      ),
                    }
                  : {},
              ],
              ['Up', raw?.startedAt ? <span title={new Date(raw.startedAt).toLocaleString()}>{dur(Date.now() - raw.startedAt)}</span> : '—'],
              ['Repos in memory', g?.cachedRepos !== undefined ? fmtNum(g.cachedRepos) : '—'],
            ]}
          />
        </div>
      </div>
    </section>
  )
}
