import { useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { useClusterView } from '../../lib/console/cluster'
import { eventRate, handleOf, handlesVersion, subscribeHandles, useFirehose, type FhEvent, type FhKind } from '../../lib/console/firehose'
import { togglePaused, useLiveState } from '../../lib/console/live'
import { clock, fmtSi, seqWriter, shortDid } from '../../lib/console/fmt'
import { Src } from './kit'
import { openPanel, usePanel } from './nav'

// The merged firehose, newest first. Filters by text (handle, DID, collection), kind and node.
// Scrolled down, new rows land above without moving what you're reading.

const KINDS: { k: FhKind; color: string }[] = [
  { k: 'commit', color: 'accent' },
  { k: 'identity', color: 'info' },
  { k: 'account', color: 'warn' },
  { k: 'sync', color: 'violet' },
]
const ROW_H = 20

const opClass = (a: string) => (a === 'create' ? 'op-c' : a === 'update' ? 'op-u' : 'op-d')

function Body({ e, handle }: { e: FhEvent; handle?: string }) {
  const who = <span className="h">{handle ? `@${handle}` : shortDid(e.did)}</span>
  if (e.kind === 'commit') {
    const o = e.ops[0]
    if (!o)
      return (
        <>
          {who} <span className="muted">empty commit</span>
        </>
      )
    return (
      <>
        {who} <span className={opClass(o.action)}>{o.action}</span> {o.path.split('/')[0]}
        {e.ops.length > 1 && <span className="muted"> +{e.ops.length - 1} ops</span>}
      </>
    )
  }
  if (e.kind === 'identity')
    return (
      <>
        {who} handle → {e.handle ?? <span className="muted">none</span>}
      </>
    )
  if (e.kind === 'account')
    return (
      <>
        {who} active={String(e.active)}
        {e.status ? ` status=${e.status}` : ''}
      </>
    )
  return (
    <>
      {who} rev {e.rev}
      {e.blocksBytes !== undefined && <span className="muted"> · {e.blocksBytes} B blocks</span>}
    </>
  )
}

export function LiveTail({ height = 280, max = 120, nodeFilter }: { height?: number; max?: number; nodeFilter?: boolean }) {
  const fh = useFirehose()
  const live = useLiveState()
  const { view } = useClusterView()
  const hv = useSyncExternalStore(subscribeHandles, handlesVersion)
  const [q, setQ] = useState('')
  const [kinds, setKinds] = useState<Set<FhKind>>(() => new Set(KINDS.map((k) => k.k)))
  const [node, setNode] = useState('')
  const panel = usePanel()
  const box = useRef<HTMLDivElement>(null)
  const lastTop = useRef<string | undefined>(undefined)

  const byWriter = useMemo(() => new Map((view?.nodes ?? []).map((n) => [n.writer, n.node])), [view])
  const nodeOf = (seq: string) => (view?.single ? view.self : byWriter.get(seqWriter(seq) ?? -1))
  const shortNode = (n?: string) => (n ? n.replace(/^vlpds-/, '') : '')

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase().replace(/^@/, '')
    const out: FhEvent[] = []
    for (let i = fh.events.length - 1; i >= 0 && out.length < max; i--) {
      const e = fh.events[i]
      if (!kinds.has(e.kind)) continue
      if (node && nodeOf(e.seq) !== node) continue
      if (ql) {
        const h = handleOf(e.did) ?? ''
        if (!h.includes(ql) && !e.did.includes(ql) && !e.ops.some((o) => o.path.includes(ql))) continue
      }
      out.push(e)
    }
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fh.events, q, kinds, node, max, byWriter, hv])

  // keep the reader's place: rows added on top push the scroll down by as much
  useLayoutEffect(() => {
    const el = box.current
    const top = rows[0]?.seq
    if (el && lastTop.current && top !== lastTop.current && el.scrollTop > 4) {
      const added = rows.findIndex((r) => r.seq === lastTop.current)
      if (added > 0) el.scrollTop += added * ROW_H
    }
    lastTop.current = top
  }, [rows])

  const rate = eventRate(fh.events)
  return (
    <>
      <div className="cx-tailbar">
        <input className="cx-inp mono" data-search placeholder="filter handle, DID or collection" value={q} onChange={(e) => setQ(e.target.value)} spellCheck={false} aria-label="Filter events" />
        {KINDS.map(({ k, color }) => (
          <button
            key={k}
            type="button"
            className={`cx-tog${kinds.has(k) ? ' on' : ''}`}
            aria-pressed={kinds.has(k)}
            onClick={() =>
              setKinds((s) => {
                const n = new Set(s)
                if (n.has(k)) n.delete(k)
                else n.add(k)
                return n
              })
            }
          >
            <span className="cx-sw" style={{ background: `var(--${color})` }} />#{k}
          </button>
        ))}
        {nodeFilter && view && !view.single && (
          <select className="cx-inp" style={{ height: 24, fontSize: 11.5, flex: 'none' }} value={node} onChange={(e) => setNode(e.target.value)} aria-label="Node">
            <option value="">all nodes</option>
            {view.nodes.map((n) => (
              <option key={n.node}>{n.node}</option>
            ))}
          </select>
        )}
        <button type="button" className={`cx-tog${live.paused ? ' on' : ''}`} onClick={togglePaused} title="Pause or resume (space)">
          {live.paused ? '▶ resume' : '❚❚ pause'}
        </button>
      </div>
      <div className="cx-tail" ref={box} style={{ height }} role="log" aria-label="Firehose events">
        {rows.map((e) => (
          <div
            key={e.id}
            className={`cx-tl-row k-${e.kind}${e.at > Date.now() - 1500 ? ' new' : ''}${panel?.type === 'event' && panel.id === e.seq ? ' on' : ''}`}
            data-open={`event:${e.seq}`}
            onClick={() => openPanel('event', e.seq)}
          >
            <span className="ts">{clock(e.at)}</span>
            <span className="sq" title={e.seq}>
              …{e.seq.slice(-8)}
            </span>
            <span className="kd">#{e.kind}</span>
            <span className="bd">
              <Body e={e} handle={handleOf(e.did)} />
            </span>
            <span className="nd">{shortNode(nodeOf(e.seq))}</span>
          </div>
        ))}
        {!rows.length && (
          <div className="cx-empty">
            {fh.status === 'open'
              ? fh.events.length
                ? 'Nothing matches the filter.'
                : 'Connected. Waiting for the next commit on this PDS.'
              : fh.status === 'connecting'
                ? 'Connecting to subscribeRepos…'
                : `Not connected${fh.error ? `: ${fh.error}` : ''}. Retrying.`}
          </div>
        )}
      </div>
      <div className="cx-tailfoot">
        <span>
          {live.paused ? (
            <span className="s-info">paused · {fh.held.toLocaleString()} events held</span>
          ) : fh.status === 'open' ? (
            <>
              <span className="s-acc">●</span> following the merged stream
            </>
          ) : (
            <span className="s-warn">▲ {fh.status === 'connecting' ? 'connecting' : 'reconnecting'}</span>
          )}
        </span>
        <span>{fmtSi(rate)} events/s</span>
        <span className="r">
          <Src>com.atproto.sync.subscribeRepos</Src>
        </span>
      </div>
    </>
  )
}
