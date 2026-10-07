import { useState, type ReactNode } from 'react'
import { confirmAction } from '../../components/console/dialogs'
import { DataTable, type Col } from '../../components/console/DataTable'
import { Chip, Meter, MiniBar, Spark, Swatch, type BannerSpec } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import type { ClusterView, NodeView } from '../../lib/console/cluster'
import { dur, factorName, fmtBytes, fmtMs, fmtNum, fmtPct, fmtSec, fmtSi, plural } from '../../lib/console/fmt'
import type { Optional, Lockout } from '../../lib/console/adminAdapter'
import { col, last, nodeGauges, nodePoints, type MetricsState } from '../../lib/console/metrics'
import { mutate } from '../../lib/console/mutate'
import { isSlow, type SubscriberList } from '../../lib/console/queries'
import { admin } from '../../lib/xrpc'

// Cluster pieces the Overview and Nodes & shards pages share.

/** Raise the active feature level (vlpds.admin.setFeatureLevel). Real: it changes the cluster. */
export function finalizeLevel(level: number, view: ClusterView) {
  const active = view.raw.version?.active
  return confirmAction({
    tone: 'warn',
    title: `Finalize feature level ${level}?`,
    items: [
      `Every live node can run it today (${view.nodes.map((n) => `${n.node} L${n.minLevel ?? '?'}–${n.maxLevel ?? '?'}`).join(', ')}).`,
      `After this, builds that can't run level ${level} can no longer join.`,
      `Rolling back becomes forward-fix only (today a plain redeploy back to level ${active ?? '?'} works).`,
    ],
    word: `level ${level}`,
    action: 'Finalize',
    call: `vlpds.admin.setFeatureLevel {"level": ${level}}`,
    run: () => mutate({ run: () => admin('vlpds.admin.setFeatureLevel', { body: { level } }), changes: [{ kind: 'config', id: 'featureLevel' }] }),
    done: `Feature level ${level} is active`,
  })
}

/** What needs the operator's eye, most urgent first. */
export function clusterBanners(view: ClusterView, subs?: SubscriberList, locks?: Optional<Lockout[]>): BannerSpec[] {
  const out: BannerSpec[] = []
  const v = view.raw.version
  const down = view.nodes.filter((n) => n.health === 'err')
  if (view.unowned)
    out.push({
      id: 'unowned',
      tone: 'err',
      title: `${plural(view.unowned, 'shard')} ${view.unowned === 1 ? 'has' : 'have'} no owner`,
      desc: 'writes to them get 503 until a node takes the lease',
      open: true,
      body: (
        <>
          The other nodes fence the dead node's log, replay its tail from the bucket and take its shards; expect seconds, not minutes. The alert{' '}
          <span className="mono">VlpdsShardsUnowned</span> pages after 2 min.
        </>
      ),
    })
  for (const n of down)
    out.push({
      id: `down-${n.node}`,
      tone: 'err',
      title: n.reachable ? `${n.node}'s lease is not valid` : `${n.node} doesn't answer`,
      desc: n.reachable ? `expired ${dur(-(n.leaseLeftMs ?? 0))} ago` : `its peer address ${n.addr} timed out`,
      open: true,
      body: (
        <>
          A node whose lease lapses fail-stops; the others fence its log <span className="mono">{n.log}</span> and take its {n.shards} shards. No acked write is lost: every ack waited
          for its segment to be durable.{' '}
          <button type="button" className="cx-linklike" onClick={() => openPanel('node', n.node)}>
            Open {n.node}
          </button>
        </>
      ),
    })
  if (v?.error) out.push({ id: 'level-err', tone: 'err', title: 'Feature level unknown', desc: v.error })
  if (v?.target != null)
    out.push({
      id: 'raising',
      tone: 'warn',
      title: `Raising the cluster to feature level ${v.target}`,
      desc: `active ${v.active}: waiting for every live node to confirm it can run it`,
      body: (
        <>
          If this stays, the finalize died between its steps: <code>vlpds admin cluster finalize --level {v.active}</code> clears it.
        </>
      ),
    })
  if (v?.mixedBuilds)
    out.push({
      id: 'mixed',
      tone: 'warn',
      title: 'Mixed builds',
      desc: v.revs.map((r) => r.slice(0, 12)).join(', '),
      body: <>Finish or roll back the deploy. Until the feature level is raised, rollback is a plain redeploy.</>,
    })
  if (v?.finalizable != null && v.target == null) {
    const f = v.finalizable
    out.push({
      id: 'finalizable',
      tone: 'info',
      title: `Feature level ${f} is ready to finalize`,
      desc: `every node runs a build that supports it · active is ${v.active}`,
      body: (
        <>
          All nodes run builds that can run level {f}. Until you finalize, rolling back is a plain redeploy; after it, older builds can't join and rollback is forward-fix only.
          CLI: <code>vlpds admin cluster finalize --level {f}</code>
          <div style={{ marginTop: 8 }}>
            <button type="button" className="cx-btn sm" onClick={() => finalizeLevel(f, view)}>
              Finalize level {f}…
            </button>
          </div>
        </>
      ),
    })
  }
  const slow = subs?.subscribers.filter(isSlow) ?? []
  if (slow.length) {
    const s = slow[0]
    out.push({
      id: 'slow',
      tone: 'warn',
      title: slow.length === 1 ? 'A firehose subscriber is falling behind' : `${slow.length} firehose subscribers are falling behind`,
      desc: (
        <>
          <span className="mono">#{s.conn}</span> on {s.node} · {s.userAgent.split(' ')[0] || s.ip}
        </>
      ),
      right: `${dur(s.lagMs ?? 0)} behind`,
      body: (
        <>
          {s.userAgent || 'No user agent'} from {s.ip ?? 'an unknown address'}
          {s.asName ? ` (${s.asName})` : ''}. Past <span className="mono">--firehose-max-lag-mb</span> unsent it gets <span className="mono">ConsumerTooSlow</span> and is disconnected.{' '}
          <button type="button" className="cx-linklike" onClick={() => openPanel('sub', `${s.node}/${s.conn}`)}>
            Open connection
          </button>
        </>
      ),
    })
  }
  const lk = locks?.supported ? locks.data : []
  if (lk.length)
    out.push({
      id: 'locked',
      tone: 'warn',
      title: `${plural(lk.length, 'account')} locked out of sign-in`,
      desc: lk.map((l) => `@${l.handle ?? l.did}`).join(', '),
      right: 'clears on its own',
      body: (
        <>
          {lk.map((l) => (
            <div key={`${l.did}/${l.factor}`}>
              @{l.handle ?? l.did}: {factorName(l.factor)} locked after {l.failures} wrong codes, clears in {dur(l.lockedUntil - Date.now())}.
            </div>
          ))}
          <div style={{ marginTop: 4 }}>Live sessions keep working while the code is locked.</div>
        </>
      ),
    })
  return out
}

/** "valid · 8.2 s left" for a node's lease. */
export function LeaseCell({ n, single }: { n: NodeView; single: boolean }) {
  if (single) return <Chip k="idle">no lease (single node)</Chip>
  if (!n.reachable) return <Chip k="err">unreachable</Chip>
  if (!n.leaseValid) return <Chip k="err">expired</Chip>
  return (
    <>
      <Chip k={n.health === 'warn' ? 'warn' : 'ok'}>valid</Chip> <span className="muted sm">{((n.leaseLeftMs ?? 0) / 1000).toFixed(1)} s left</span>
    </>
  )
}

export const NodeTag = ({ n }: { n: Pick<NodeView, 'node' | 'color' | 'self'> }) => (
  <span className="cx-cellid">
    <Swatch color={n.color} />
    <span className="mono">{n.node}</span>
    {n.self && <Chip k="acc">this node</Chip>}
  </span>
)

const NO_METRICS = 'Per-node metrics: this node only, or every node once the server has vlpds.admin.getNodeMetrics'

/** Every node: lease, shards, write rate and latency, watermark lag, build. */
export function NodesTable({ view, metrics, compact }: { view: ClusterView; metrics: MetricsState; compact?: boolean }) {
  const pts = (n: NodeView) => nodePoints(metrics, n.node, n.self)
  const g = (n: NodeView) => nodeGauges(metrics, n.node, n.self)
  const total = view.table.length || 1
  const cols: Col<NodeView>[] = [
    { id: 'node', label: 'Node', sort: (a, b) => a.node.localeCompare(b.node), render: (n) => <NodeTag n={n} /> },
    { id: 'lease', label: 'Lease', render: (n) => <LeaseCell n={n} single={view.single} /> },
    {
      id: 'shards',
      label: 'Shards',
      r: true,
      sort: (a, b) => a.shards - b.shards,
      render: (n) => (
        <span className="cx-cellid end">
          {fmtNum(n.shards)}
          <MiniBar parts={[{ v: n.shards, color: n.color ?? 'var(--ink3)' }, { v: total - n.shards, color: 'transparent' }]} />
        </span>
      ),
    },
    {
      id: 'commits',
      label: 'Commits/s',
      style: { width: 120 },
      render: (n) => {
        const p = pts(n)
        if (!p) return <span className="muted" title={NO_METRICS}>—</span>
        return (
          <>
            <Spark data={col(p, 'commits')} color={n.color?.match(/--(c\d)/)?.[1] ?? 'accent'} size="inline" /> <span className="mono sm">{fmtSi(last(p, 'commits') ?? NaN)}</span>
          </>
        )
      },
    },
    { id: 'p99', label: 'p99', title: 'Commit to durable, p99 over the last interval', r: true, render: (n) => <span className="mono">{pts(n) ? fmtSec(last(pts(n), 'durP99')) : '—'}</span> },
    {
      id: 'wm',
      label: 'Watermark lag',
      title: "How far this log's firehose watermark trails now",
      r: true,
      sort: (a, b) => (a.wmLagMs ?? 0) - (b.wmLagMs ?? 0),
      render: (n) => (
        <span className={`mono${n.slowest ? ' s-warn' : ''}`} title={n.slowest ? 'Slowest log: it sets the firehose watermark' : undefined}>
          {fmtMs(n.wmLagMs)}
        </span>
      ),
    },
    ...(compact
      ? []
      : ([
          { id: 'ord', label: 'Durable ordinal', r: true, render: (n) => <span className="mono">{n.logDurableOrdinal != null ? fmtNum(n.logDurableOrdinal) : '—'}</span> },
          {
            id: 'mem',
            label: 'Memory',
            r: true,
            render: (n) => {
              const x = g(n)
              if (x?.resident === undefined) return <span className="muted" title={NO_METRICS}>—</span>
              const frac = x.memLimit ? x.resident / x.memLimit : 0
              return (
                <>
                  {x.memLimit ? <Meter v={x.resident} max={x.memLimit} k={frac > 0.85 ? 'warn' : 'ok'} /> : null} <span className="mono sm">{fmtBytes(x.resident)}</span>
                </>
              )
            },
          },
          { id: 'cpu', label: 'CPU', r: true, render: (n) => <span className="mono">{pts(n) ? fmtPct(last(pts(n), 'cpu')) : '—'}</span> },
        ] as Col<NodeView>[])),
    {
      id: 'build',
      label: 'Build',
      render: (n) =>
        n.rev ? (
          <span className="mono sm t2" title={n.seenLevel ? `${n.rev} · last read active level ${n.seenLevel}` : n.rev}>
            {n.rev.slice(0, 8)}{' '}
            {n.maxLevel != null && (
              <span className={n.maxLevel > (view.raw.version?.active ?? n.maxLevel) ? 's-warn' : 'muted'}>
                L{n.minLevel === n.maxLevel ? n.maxLevel : `${n.minLevel}–${n.maxLevel}`}
              </span>
            )}
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
  ]
  return (
    <DataTable
      label="Nodes"
      rows={view.nodes}
      cols={cols}
      rowKey={(n) => n.node}
      open={(n) => ({ type: 'node', id: n.node })}
      dim={(n) => n.health === 'err'}
      compact
    />
  )
}

/** One square per shard in slot order, coloured by owner; striped red when nobody owns it. */
export function ShardMap({ view, focus, only, onShard }: { view: ClusterView; focus?: string; only?: string; onShard?: (i: number) => void }) {
  const [hover, setHover] = useState<number>()
  const n = view.table.length
  const cols = n <= 16 ? n : n <= 256 ? 16 : 32
  const ids = view.raw.layout?.shards.map((s) => s.id)
  const mine = new Set(view.raw.owned)
  const isMine = (i: number) => !only && !view.single && (ids ? mine.has(ids[i]) : mine.has(i))
  const colorOf = (o: string | null) => (o ? view.nodes.find((x) => x.node === o)?.color : undefined)
  const info = (i: number): ReactNode => {
    const o = view.table[i]
    const r = view.raw.layout?.shards[i]
    return (
      <>
        Shard <b className="mono">{r ? r.id : i}</b>
        {r && (
          <>
            {' '}
            · hash slots {r.lo}–{r.hi - 1}
          </>
        )}{' '}
        · {o ? <span className="mono">{o}</span> : <span className="s-err">no owner: writes get 503</span>}
        {isMine(i) && ' (this node)'}
      </>
    )
  }
  return (
    <>
      <div className={`cx-shardmap${focus ? ' focus' : ''}`} style={{ ['--cols' as string]: cols }} onMouseLeave={() => setHover(undefined)}>
        {view.table.map((o, i) => (
          <button
            key={i}
            type="button"
            className={`cx-shard${o ? '' : ' unowned'}${isMine(i) ? ' mine' : ''}${focus && o === focus ? ' hl' : ''}`}
            style={o && (!only || o === only) ? { background: colorOf(o) } : undefined}
            aria-label={`Shard ${i}: ${o ?? 'unowned'}`}
            onMouseEnter={() => setHover(i)}
            onFocus={() => setHover(i)}
            onClick={() => (onShard ? onShard(i) : openPanel('shard', String(i)))}
          />
        ))}
      </div>
      <div className="cx-shardinfo" aria-live="polite">
        {hover !== undefined ? (
          info(hover)
        ) : (
          <>
            Hover a shard for its owner, click for its details.{!view.single && !only && ' A light centre marks this node’s shards.'}
          </>
        )}
      </div>
    </>
  )
}
