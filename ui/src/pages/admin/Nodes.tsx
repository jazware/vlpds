import { useState, type Dispatch, type SetStateAction } from 'react'
import { Banners, Chip, Copy, ErrorState, KV, Loading, Mini, Minis, PageHead, Panel, PanelBody, Spark, Src } from '../../components/console/kit'
import { registerPalette } from '../../components/console/Palette'
import { openPanel } from '../../components/console/nav'
import { clusterPoll, clusterView, useClusterView, type ClusterView } from '../../lib/console/cluster'
import { ago, dur, fmtBytes, fmtMs, fmtNum, fmtPct, fmtSec, fmtSi, plural } from '../../lib/console/fmt'
import { useStartedAt } from '../../lib/console/nodeMetrics'
import { col, last, nodeGauges, nodePoints, useMetrics, type MetricsState } from '../../lib/console/metrics'
import { lockoutsPoll, subscribersPoll } from '../../lib/console/polls'
import { Link } from '../../lib/router'
import { clusterBanners, finalizeLevel, LeaseCell, NodesTable, ShardMap } from './clusterUi'
import { OneNode } from './nodeSolo'

// Nodes & shards: one card per node, shard ownership, the firehose merge, the feature level,
// and every node in a table; a cluster of one gets one panel for its node (nodeSolo.tsx).

// "Finalize level N" in ⌘K while a level is ready
registerPalette({
  items: () => {
    const c = clusterPoll.get().data
    const f = c?.version?.finalizable
    if (!c || f == null || c.version?.target != null) return []
    return [{ group: 'Actions', title: `Finalize feature level ${f}…`, desc: `active is ${c.version?.active}`, always: true, run: () => finalizeLevel(f, clusterView(c)) }]
  },
})

export function Nodes() {
  const { view, error, at } = useClusterView()
  const m = useMetrics()
  const subs = subscribersPoll.use()
  const locks = lockoutsPoll.use()
  const [focus, setFocus] = useState<string>()
  if (!view) return error ? <ErrorState error={error} retry={clusterPoll.refresh} /> : <Loading label="Asking the cluster…" />
  const v = view.raw.version
  const one = view.nodes.length === 1
  return (
    <>
      <PageHead
        title={
          view.single ? (
            <>Single node</>
          ) : one ? (
            <>
              Single node <span className="mono">{view.self}</span>
            </>
          ) : (
            <>
              Cluster <span className="muted" style={{ fontWeight: 500 }}>as seen by</span> <span className="mono">{view.self}</span>
            </>
          )
        }
        sub={
          <>
            <span>{fmtNum(view.table.length)} shards</span>
            {!view.single && <span>{one ? 'a cluster of one, holding the lease' : `${plural(view.nodes.length, 'node')} holding a lease`}</span>}
            {v && (
              <span>
                feature level {v.active ?? '—'}
                {v.finalizable != null && ` · ${v.finalizable} ready`}
              </span>
            )}
            {view.raw.layout && <span>layout v{view.raw.layout.version}</span>}
          </>
        }
        actions={
          <>
            {v?.finalizable != null && v.target == null && (
              <button type="button" className="cx-btn" onClick={() => finalizeLevel(v.finalizable!, view)}>
                Finalize level {v.finalizable}…
              </button>
            )}
            <Link className="cx-btn" to="/admin/metrics">
              All charts
            </Link>
          </>
        }
      />
      <Banners items={clusterBanners(view, subs.data, locks.data)} />
      {view.nodes.length === 1 ? (
        <OneNode view={view} n={view.nodes[0]} m={m} subs={subs.data} at={at} />
      ) : (
        <Many view={view} m={m} focus={focus} setFocus={setFocus} />
      )}
    </>
  )
}

/** Up to this many nodes the cards say everything the table would; past it the table is the overview. */
const CARDS_ONLY = 3

function Many({ view, m, focus, setFocus }: { view: ClusterView; m: MetricsState; focus?: string; setFocus: Dispatch<SetStateAction<string | undefined>> }) {
  const v = view.raw.version
  const started = useStartedAt()
  const fenced = Object.entries(view.raw.fencedLogs)
  const live = new Set(view.nodes.map((n) => n.log))
  const draining = view.raw.firehose.sources.filter((s) => !live.has(s.log))
  return (
    <>
      <div className="cx-nodecards cx-mb">
        {view.nodes.map((n) => {
          const p = nodePoints(m, n.node, n.self)
          const g = nodeGauges(m, n.node, n.self)
          return (
            <section key={n.node} className="cx-pn" data-open={`node:${n.node}`} style={{ cursor: 'pointer' }} onClick={(e) => !(e.target as HTMLElement).closest('button,a') && openPanel('node', n.node)}>
              <div className="cx-pn-h">
                <span className="cx-sw" style={{ background: n.color }} />
                <h3 className="mono" style={{ textTransform: 'none', letterSpacing: '-.01em', color: 'var(--ink)', fontSize: 13.5 }}>
                  {n.node}
                </h3>
                {n.self && <Chip k="acc">this node</Chip>}
                <div className="r">
                  <LeaseCell n={n} single={view.single} />
                </div>
              </div>
              {p ? (
                <Minis n={3}>
                  <Mini label="commits/s" value={fmtSi(last(p, 'commits') ?? NaN)}>
                    <Spark data={col(p, 'commits')} color={n.color?.match(/--(c\d)/)?.[1] ?? 'accent'} />
                  </Mini>
                  <Mini label="p99" value={fmtSec(last(p, 'durP99'))}>
                    <Spark data={col(p, 'durP99')} color="amber" />
                  </Mini>
                  <Mini label="cpu" value={fmtPct(last(p, 'cpu'))}>
                    <Spark data={col(p, 'cpu')} color="c6" />
                  </Mini>
                </Minis>
              ) : (
                <div className="cx-minis muted sm" style={{ ['--n' as string]: 1 }}>
                  No metrics for this node{m.source === 'local' ? ': the console scrapes only the node serving it until the server fans /metrics out' : ''}.
                </div>
              )}
              <div style={{ padding: '0 12px 12px' }}>
                <KV
                  style={{ gridTemplateColumns: '110px minmax(0,1fr)' }}
                  rows={[
                    ['log', <span className="mono">{n.log}{n.logDurableOrdinal != null && <span className="muted"> @ {fmtNum(n.logDurableOrdinal)}</span>}</span>],
                    ['watermark lag', <span className="mono">{fmtMs(n.wmLagMs)}{n.slowest && <> <Chip k="warn">slowest log</Chip></>}</span>],
                    ['shards', <>{n.shards}{!view.single && <> · writer byte {n.writer}</>}</>],
                    ['memory', g?.resident !== undefined ? <span className="mono">{fmtBytes(g.resident)}{g.memLimit ? <span className="muted"> of {fmtBytes(g.memLimit)}</span> : null}</span> : '—'],
                    [
                      'build',
                      <span className="mono">
                        {n.rev ? n.rev.slice(0, 12) : '—'} {n.rev && <span className="muted">L{n.minLevel}–{n.maxLevel}</span>}
                        {started.get(n.node) && (
                          <span className="muted" title={`started ${new Date(started.get(n.node)!).toLocaleString()}`}>
                            {' '}
                            · up {dur(Date.now() - started.get(n.node)!)}
                          </span>
                        )}
                      </span>,
                    ],
                    ...(n.addr ? [['address', <Copy text={n.addr.replace(/^https?:\/\//, '')} />] as [string, React.ReactNode]] : []),
                  ]}
                />
              </div>
            </section>
          )
        })}
      </div>
      <div className="cx-grid2">
        <Panel
          title="Shard ownership"
          src={<Src>getClusterStatus · table</Src>}
          right={
            <>
              {view.nodes.map((n) => (
                <button key={n.node} type="button" className={`cx-tog${focus === n.node ? ' on' : ''}`} aria-pressed={focus === n.node} onClick={() => setFocus((f) => (f === n.node ? undefined : n.node))}>
                  <span className="cx-sw" style={{ background: n.color }} />
                  {n.node} · {n.shards}
                </button>
              ))}
              {view.unowned > 0 && <Chip k="err">{view.unowned} unowned</Chip>}
            </>
          }
        >
          <PanelBody>
            <ShardMap view={view} focus={focus} />
          </PanelBody>
        </Panel>
        <div className="cx-stack">
          <Panel title="Firehose merge" src={<Src>getClusterStatus · firehose</Src>}>
            <PanelBody>
              <KV
                rows={[
                  ['last emitted', view.raw.firehose.lastEmitted !== '0' ? <Copy text={view.raw.firehose.lastEmitted} /> : '—'],
                  ['min watermark', view.wmLagMs !== undefined ? <>{fmtMs(view.wmLagMs)} behind now <span className="muted">· set by the slowest log</span></> : '—'],
                  ['sources', `${view.raw.firehose.sources.length} logs (${view.raw.firehose.sources.filter((s) => s.local).length} local)`],
                  ...(draining.length ? [['draining', draining.map((s) => <div key={s.log} className="mono sm">{s.log}</div>)] as [string, React.ReactNode]] : []),
                  ...(fenced.length ? [['fenced', fenced.map(([l, end]) => <div key={l} className="mono sm">{l}@{end}</div>)] as [string, React.ReactNode]] : []),
                ]}
              />
            </PanelBody>
          </Panel>
          {v && (
            <Panel title="Feature level" src={<Src>cluster/version</Src>} right={v.finalizable != null ? <Chip k="info">{v.finalizable} ready</Chip> : v.mixedBuilds ? <Chip k="warn">mixed builds</Chip> : undefined}>
              <PanelBody>
                <KV
                  rows={[
                    ['active', <><b>{v.active ?? '—'}</b>{v.finalizedAt && <> · finalized {ago(Date.parse(v.finalizedAt))}</>}</>],
                    ['builds can run', `${Math.max(...view.nodes.map((n) => n.minLevel ?? 0))}–${Math.min(...view.nodes.map((n) => n.maxLevel ?? 0))} on every node`],
                    ['this build', <span className="mono">{v.binary.rev.slice(0, 12)} · L{v.binary.min}–{v.binary.max}</span>],
                    ['history', v.history.length ? v.history.slice(-4).map((h) => `L${h.level} ${new Date(h.at).toLocaleDateString()}`).join(' · ') : '—'],
                  ]}
                />
              </PanelBody>
            </Panel>
          )}
        </div>
      </div>
      {view.nodes.length > CARDS_ONLY && (
        <Panel title="All nodes" className="cx-mt" src={<Src>getClusterStatus</Src>}>
          <NodesTable view={view} metrics={m} />
        </Panel>
      )}
    </>
  )
}
