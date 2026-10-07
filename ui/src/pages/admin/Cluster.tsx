import { useMemo, useState } from 'react'
import { CopyText, CopyValue, ErrorNotice, Loading, Notice, Panel, Status } from '../../components/ui'
import { clusterQ } from '../../lib/console/cluster'
import { fmtNum, fmtTime, relTime, seqMillis } from '../../lib/format'

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
  /** Build (git rev) and the feature levels it can run; the active level it last read. */
  rev?: string
  minLevel?: number
  maxLevel?: number
  seenLevel?: number
}

/** `cluster/version` and what the banner says (src/xrpc/webui.rs `feature_levels`). */
export type FeatureLevels = {
  active: number | null
  target: number | null
  history: { level: number; at: string; by: string }[]
  binary: { min: number; max: number; rev: string }
  mixedBuilds: boolean
  revs: string[]
  /** Highest level every live node can run, when above the active one. */
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
}

const SLOTS = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6']

/**
 * A node's color, fixed by its position among node ids so a node keeps its color while it lives.
 * Up to six nodes use the theme's categorical slots; past that, hues are spread evenly around the
 * wheel with alternating lightness so neighbours stay distinguishable.
 */
function colorOf(nodes: string[], id: string): string | undefined {
  const i = nodes.indexOf(id)
  if (i < 0) return undefined
  if (nodes.length <= SLOTS.length) return `var(--${SLOTS[i]})`
  const hue = Math.round(160 + (i * 360) / nodes.length) % 360
  return `oklch(${i % 2 ? 0.6 : 0.74} 0.13 ${hue})`
}

export function useLive(updated?: number) {
  const age = updated ? Date.now() - updated : Infinity
  return age < 6000
}

export function Cluster() {
  // the console's one getClusterStatus copy (its own types are a superset of this page's)
  const c = clusterQ.use() as { data?: ClusterStatus & { fetchedAt: number }; error?: unknown }
  const [focus, setFocus] = useState<string>()
  const d = c.data
  const live = useLive(d?.fetchedAt) && !c.error
  if (!d)
    return (
      <>
        <ErrorNotice error={c.error} />
        {!c.error && <Loading />}
      </>
    )
  const lastMs = seqMillis(d.firehose.lastEmitted)
  const wmMs = seqMillis(d.firehose.minWatermark)
  const allIds = [...new Set([...d.nodes.map((n) => n.node), ...(d.table.filter(Boolean) as string[])])].sort()
  const wmLag = wmMs !== undefined ? Math.max(0, d.time - wmMs) : undefined
  const toggle = (id: string) => setFocus((f) => (f === id ? undefined : id))
  return (
    <>
      <div className="console-head">
        <h1>
          Cluster <span className="muted">as seen by</span> <span className="mono">{d.node || 'single node'}</span>
        </h1>
        <span className={`live${live ? '' : ' stale'}`} aria-live="polite">
          <i aria-hidden="true" />
          {live ? 'Live, every 2 s' : 'Not updating'}
        </span>
      </div>
      <ErrorNotice error={c.error} />
      {d.version && <LevelsBanner v={d.version} />}
      <div className="tiles">
        <div className="tile">
          <div className="v">{d.nodes.length || 1}</div>
          <div className="k">Nodes with a lease</div>
        </div>
        <div className="tile">
          <div className="v">
            {d.owned.length}
            <small>/ {d.shards}</small>
          </div>
          <div className="k">Shards owned by this node</div>
        </div>
        <div className="tile" title={d.leaseExpiresMs ? `Renews before ${new Date(d.leaseExpiresMs).toLocaleTimeString()}` : undefined}>
          <div className="v">{d.leaseValid ? <Status kind="ok">Valid</Status> : <Status kind="bad">Expired</Status>}</div>
          <div className="k">This node's lease</div>
        </div>
        <div className="tile">
          <div className="v">{d.logDurableOrdinal ?? '—'}</div>
          <div className="k">Durable log ordinal</div>
        </div>
        {d.version && (
          <div className="tile" title={`This build runs levels ${d.version.binary.min}–${d.version.binary.max} (rev ${d.version.binary.rev})`}>
            <div className="v">
              {d.version.active ?? '—'}
              {d.version.target != null && <small>→ {d.version.target}</small>}
            </div>
            <div className="k">Feature level</div>
          </div>
        )}
        <div className="tile">
          <div className="v">{lastMs ? relTime(lastMs) : '—'}</div>
          <div className="k">Last firehose event</div>
        </div>
        <div className="tile">
          <div className="v">
            {wmLag !== undefined ? fmtNum(wmLag) : '—'}
            <small>ms</small>
          </div>
          <div className="k">Watermark behind now</div>
        </div>
      </div>

      <div className="cluster-grid">
        <Panel title="Shard ownership" desc={`${d.shards} hash-slot ranges, colored by owner. Click a node to highlight its shards.`}>
          <ShardMap d={d} ids={allIds} focus={focus} />
        </Panel>
        <div>
          <NodesPanel d={d} ids={allIds} focus={focus} onFocus={toggle} />
          <FirehosePanel d={d} />
        </div>
      </div>
    </>
  )
}

function NodesPanel({ d, ids, focus, onFocus }: { d: ClusterStatus; ids: string[]; focus?: string; onFocus: (id: string) => void }) {
  const counts = useMemo(() => {
    const m = new Map<string, number>()
    for (const o of d.table) if (o) m.set(o, (m.get(o) ?? 0) + 1)
    return m
  }, [d.table])
  const wm = useMemo(() => new Map(d.firehose.sources.map((s) => [s.log, s.watermark])), [d.firehose.sources])
  const unowned = d.table.filter((o) => !o).length
  return (
    <Panel
      title="Nodes"
      desc="Every node holding a lease, as reported by the node itself."
      flush
      actions={unowned > 0 ? <span className="pill amber">{unowned} shards unowned</span> : undefined}
    >
      <div className="table-wrap">
        <table className="data compact nodes">
          <thead>
            <tr>
              <th>Node</th>
              <th>Address</th>
              <th className="num">Writer</th>
              <th>Lease</th>
              <th className="num" title="Last durable segment ordinal in the node's log">Durable</th>
              <th className="num" title="How far this log's firehose watermark trails now">Firehose lag</th>
              <th className="num">Shards</th>
              <th title="Git revision and the feature levels the node's build can run">Build</th>
            </tr>
          </thead>
          <tbody>
            {d.nodes.map((n) => {
              const color = colorOf(ids, n.node)
              const ms = seqMillis(wm.get(n.log))
              const slowest = d.firehose.sources.length > 1 && wm.get(n.log) === d.firehose.minWatermark
              return (
                <tr
                  key={n.node}
                  className={`link${focus === n.node ? ' sel' : ''}`}
                  onClick={() => onFocus(n.node)}
                  aria-selected={focus === n.node}
                >
                  <td title={`Log ${n.log}`}>
                    <span className="node-id">
                      <span className="sw" style={{ background: color ?? 'var(--ink3)' }} />
                      <b className="mono">{n.node}</b>
                      {n.self && <span className="pill accent">this node</span>}
                    </span>
                  </td>
                  <td className="small muted">
                    <CopyValue text={n.addr.replace(/^https?:\/\//, '')} label={`Copy address ${n.addr}`} title={`${n.addr} (click to copy)`} />
                  </td>
                  <td className="num mono">{n.writer}</td>
                  <td title={`Lease expires ${relTime(n.expiresMs)}`}>
                    {!n.reachable ? (
                      <Status kind="bad">Unreachable</Status>
                    ) : n.leaseValid ? (
                      <Status kind="ok">Valid</Status>
                    ) : (
                      <Status kind="warn">Expired</Status>
                    )}{' '}
                    <span className="small muted">{relTime(n.expiresMs).replace(/^in (.*)$/, '$1 left')}</span>
                  </td>
                  <td className="num mono" title={n.logDurableOrdinal == null ? 'No segments written yet' : undefined}>
                    {n.logDurableOrdinal ?? <span className="muted">—</span>}
                  </td>
                  <td className={`num${slowest ? ' slowest' : ''}`} title={slowest ? 'Slowest log: it sets the firehose watermark' : undefined}>
                    {ms ? `${fmtNum(Math.max(0, d.time - ms))} ms` : '—'}
                  </td>
                  <td className="num">{n.owned ?? counts.get(n.node) ?? '—'}</td>
                  <td className="mono small" title={n.seenLevel ? `Last read active level ${n.seenLevel}` : undefined}>
                    {n.rev ? <CopyValue text={n.rev} display={n.rev.slice(0, 12)} label={`Copy build ${n.rev}`} title={`${n.rev} (click to copy)`} /> : '—'}{' '}
                    {n.maxLevel != null && (
                      <span className={n.maxLevel > (d.version?.active ?? n.maxLevel) ? 'pill amber' : 'muted'}>
                        L{n.minLevel === n.maxLevel ? n.maxLevel : `${n.minLevel}–${n.maxLevel}`}
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

/** Firehose merge state. Per-node lag lives in the Nodes table; this lists only logs no live node owns (draining or dead). */
function FirehosePanel({ d }: { d: ClusterStatus }) {
  const live = new Set(d.nodes.map((n) => n.log))
  const orphans = d.firehose.sources.filter((s) => !live.has(s.log))
  const fenced = Object.entries(d.fencedLogs)
  return (
    <Panel title="Firehose" desc="Events go out once every log's watermark has passed them; the slowest log holds the stream back.">
      <dl className="dl compact">
        <dt>Last emitted</dt>
        <dd>
          <CopyText text={d.firehose.lastEmitted} />
        </dd>
        <dt>Min watermark</dt>
        <dd>{d.firehose.minWatermark ? <CopyText text={d.firehose.minWatermark} /> : '—'}</dd>
        <dt>Sources</dt>
        <dd>
          {d.firehose.sources.length} logs ({d.firehose.sources.filter((s) => s.local).length} local)
        </dd>
        {orphans.length > 0 && (
          <>
            <dt>Draining</dt>
            <dd>
              {orphans.map((s) => (
                <div key={s.log} className="mono small">
                  {s.log} <span className="muted">· {fmtNum(Math.max(0, d.time - (seqMillis(s.watermark) ?? d.time)))} ms behind</span>
                </div>
              ))}
            </dd>
          </>
        )}
        {fenced.length > 0 && (
          <>
            <dt>Fenced</dt>
            <dd>
              {fenced.map(([log, end]) => (
                <div key={log} className="mono small">
                  {log}@{end}
                </div>
              ))}
            </dd>
          </>
        )}
      </dl>
    </Panel>
  )
}

function ShardMap({ d, ids, focus }: { d: ClusterStatus; ids: string[]; focus?: string }) {
  const [hover, setHover] = useState<number>()
  const n = d.shards
  const cols = n <= 16 ? n : n <= 256 ? 16 : 32
  const table = d.table.length ? d.table : Array.from({ length: n }, (_, i) => (d.owned.includes(i) ? d.node : null))
  const mine = new Set(d.owned)
  const h = hover !== undefined ? table[hover] : undefined
  return (
    <>
      <div
        className={`shardmap${focus ? ' focus' : ''}${ids.length > 1 ? ' multi' : ''}`}
        style={{ ['--cols' as any]: cols }}
        role="grid"
        aria-label="Shard ownership map"
        onMouseLeave={() => setHover(undefined)}
      >
        {table.map((owner, i) => {
          const color = owner ? colorOf(ids, owner) : undefined
          return (
            <button
              key={i}
              type="button"
              className={`shard${owner ? '' : ' unowned'}${mine.has(i) ? ' mine' : ''}${focus && owner === focus ? ' hl' : ''}`}
              style={color ? { background: color } : undefined}
              aria-label={`Shard ${i}: ${owner ?? 'unowned'}${mine.has(i) ? ' (this node)' : ''}`}
              onMouseEnter={() => setHover(i)}
              onFocus={() => setHover(i)}
            />
          )
        })}
      </div>
      <div className="inspect" aria-live="polite">
        {hover !== undefined ? (
          <>
            Shard <b className="mono">{hover}</b> — {h ? <span className="mono">{h}</span> : 'no owner'}
            {mine.has(hover) && ' (this node)'}
          </>
        ) : (
          <>
            {ids.length > 1 && 'A light center marks this node’s shards. '}Striped shards are unowned; writes to them get 503 until a node takes the lease.
          </>
        )}
      </div>
    </>
  )
}

/**
 * Rolling-upgrade state (DESIGN.md "Rolling upgrades and format versioning"): a raise in progress,
 * mixed builds (rollback is a plain redeploy until the level is raised), a level every node can now
 * run (finalize available), or the time the active level was raised (older builds can't join).
 */
function LevelsBanner({ v }: { v: FeatureLevels }) {
  if (v.error) return <Notice kind="err">Feature level unknown: {v.error}</Notice>
  if (v.target != null)
    return (
      <Notice kind="warn">
        Raising the cluster to feature level <b>{v.target}</b> (active {v.active}): waiting for every live node to confirm it can run it. If this stays, the finalize died between its steps: <code>vlpds admin cluster finalize --level {v.active}</code> clears it.
      </Notice>
    )
  const notes = []
  if (v.mixedBuilds)
    notes.push(
      <Notice kind="warn" key="mixed">
        Mixed builds: <span className="mono">{v.revs.map((r) => r.slice(0, 12)).join(', ')}</span>. Finish or roll back the deploy;
        until the feature level is raised, rollback is a plain redeploy.
      </Notice>,
    )
  if (v.finalizable != null)
    notes.push(
      <Notice key="final">
        Every node can run feature level <b>{v.finalizable}</b> (active {v.active}). After the soak, finalize with{' '}
        <code>vlpds admin cluster finalize --level {v.finalizable}</code>; from then on rollback is forward-fix only.
      </Notice>,
    )
  else if (v.finalizedAt && !v.mixedBuilds)
    notes.push(
      <Notice kind="ok" key="done">
        Feature level {v.active} finalized on {fmtTime(v.finalizedAt)}: builds that can't run it can no longer join (rollback by redeploy is no
        longer possible).
      </Notice>,
    )
  return <>{notes}</>
}
