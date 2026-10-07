import { confirmAction } from '../../components/console/dialogs'
import { registerDetail } from '../../components/console/Drawer'
import { Chip, Copy, Glyph, Json, KV, Mini, Minis, RRow, Sec, Spark, Src, Strip } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import { kickSubscriber } from '../../lib/console/adminAdapter'
import { useClusterView } from '../../lib/console/cluster'
import { findEvent, useFirehose, useHandle } from '../../lib/console/firehose'
import { clock, dur, fmtBytes, fmtMs, fmtNum, fmtPct, fmtSec, fmtSi, plural, seqMillis, seqWriter } from '../../lib/console/fmt'
import { col, last, nodeGauges, nodePoints, useMetrics } from '../../lib/console/metrics'
import { isSlow, subscribersPoll } from '../../lib/console/polls'
import { LeaseCell, NodeTag, ShardMap } from './clusterUi'

// Slide-over / full-page details for the cluster sections: node, shard, firehose event,
// firehose connection. Registered on import (AdminApp imports this file).


registerDetail('node', {
  kind: 'Node',
  section: 'nodes',
  use: (id, mode) => {
    const { view } = useClusterView()
    const m = useMetrics()
    const subs = subscribersPoll.use()
    const n = view?.nodes.find((x) => x.node === id)
    if (!view) return { title: id, body: null, loading: true }
    if (!n) return { title: <span className="mono">{id}</span>, body: null, missing: `${id} holds no lease right now: it left the cluster or never joined.` }
    const p = nodePoints(m, n.node, n.self)
    const g = nodeGauges(m, n.node, n.self)
    const page = mode === 'page'
    const here = subs.data?.subscribers.filter((s) => s.node === n.node) ?? []
    const v = view.raw.version
    return {
      title: <span className="mono">{n.node}</span>,
      chip: n.health === 'err' ? <Chip k="err">down</Chip> : n.health === 'warn' ? <Chip k="warn">lease late</Chip> : <Chip k="ok">healthy</Chip>,
      foot: (
        <>
          <Src>getClusterStatus · 2 s</Src> {p ? `metrics from ${m.source === 'fanout' ? 'the peer fan-out' : 'this node’s /metrics'}` : 'no metrics for this node'}
        </>
      ),
      body: (
        <>
          <Strip
            items={[
              ['commits/s', p ? fmtSi(last(p, 'commits') ?? NaN) : '—'],
              ['commit p99', p ? fmtSec(last(p, 'durP99')) : '—'],
              ['cpu', p ? fmtPct(last(p, 'cpu')) : '—'],
              [g?.memLimit ? `memory of ${fmtBytes(g.memLimit)}` : 'memory', g?.resident !== undefined ? fmtBytes(g.resident) : '—'],
              ['shards', fmtNum(n.shards)],
              ['subscribers', fmtNum(here.length)],
            ]}
          />
          {p && (
            <Minis n={3} style={{ padding: 0 }}>
              <Mini label="commits/s" value={fmtSi(last(p, 'commits') ?? NaN)}>
                <Spark data={col(p, 'commits')} color="accent" />
              </Mini>
              <Mini label="commit → durable p99" value={fmtSec(last(p, 'durP99'))}>
                <Spark data={col(p, 'durP99')} l2={col(p, 'durP50')} color="amber" />
              </Mini>
              {last(p, 'leaseRatioP99') !== undefined ? (
                <Mini label="lease renew ÷ TTL p99" value={last(p, 'leaseRatioP99')!.toFixed(3)}>
                  <Spark data={col(p, 'leaseRatioP99')} color="violet" th={0.2} />
                </Mini>
              ) : (
                <Mini label="segment PUT p99" value={fmtSec(last(p, 'putP99'))}>
                  <Spark data={col(p, 'putP99')} l2={col(p, 'putP50')} color="violet" />
                </Mini>
              )}
            </Minis>
          )}
          <Sec title="Lease" digest={view.single ? 'single node' : n.leaseValid ? 'valid' : 'expired'} open>
            <KV
              rows={[
                ['State', <LeaseCell key="l" n={n} single={view.single} />],
                ['Object', <span className="mono">nodes/{n.node}</span>],
                ['Renewal', 'by compare-and-swap; a renewal round trip over 0.4 × TTL fail-stops the node (exit 5)'],
                ['Peer address', n.addr ? <Copy text={n.addr} /> : '—'],
              ]}
            />
          </Sec>
          <Sec title="Shards" digest={`${n.shards} of ${view.table.length}`} open>
            <ShardMap view={view} only={n.node} />
          </Sec>
          <Sec title="Log" digest={`${n.log} @ ${n.logDurableOrdinal ?? '—'}`} open={page}>
            <KV
              rows={[
                ['Log id', <Copy text={n.log} />],
                ['Writer byte', <span className="mono">{n.writer} <span className="muted">(low byte of every seq it assigns)</span></span>],
                ['Durable ordinal', <span className="mono">{n.logDurableOrdinal != null ? fmtNum(n.logDurableOrdinal) : 'no segments yet'}</span>],
                ['Watermark lag', <>{fmtMs(n.wmLagMs)}{n.slowest && <> <Chip k="warn">slowest log</Chip></>}</>],
                ['Segment PUT p99', p ? fmtSec(last(p, 'putP99')) : '—'],
              ]}
            />
          </Sec>
          <Sec title="Build" digest={n.rev ? `${n.rev.slice(0, 12)} · levels ${n.minLevel}–${n.maxLevel}` : '—'} open={page}>
            <KV
              rows={[
                ['Revision', n.rev ? <Copy text={n.rev} /> : '—'],
                ['Can run levels', n.minLevel != null ? `${n.minLevel}–${n.maxLevel}` : '—'],
                ['Last read level', n.seenLevel ?? '—'],
                ['Cluster level', v ? `${v.active ?? '—'}${v.finalizable ? ` (${v.finalizable} ready)` : ''}` : '—'],
                ['Repos in memory', g?.cachedRepos !== undefined ? fmtNum(g.cachedRepos) : '—'],
              ]}
            />
          </Sec>
          <Sec title="Firehose subscribers here" digest={plural(here.length, 'connection')} open={page} flush>
            {here.length ? (
              here.map((s) => (
                <RRow key={s.conn} onClick={() => openPanel('sub', `${s.node}/${s.conn}`)} x={s.state === 'backfilling' ? 'backfilling' : isSlow(s) ? `${dur(s.lagMs ?? 0)} behind` : 'caught up'}>
                  <Glyph k={s.state === 'backfilling' ? 'info' : isSlow(s) ? 'warn' : 'ok'} />
                  <span className="mono sm">#{s.conn}</span>
                  <span className="nm">{s.relay ?? s.userAgent.split(' ')[0] ?? s.ip}</span>
                </RRow>
              ))
            ) : (
              <div className="cx-empty">None.</div>
            )}
          </Sec>
        </>
      ),
    }
  },
})

registerDetail('shard', {
  kind: 'Shard',
  section: 'nodes',
  use: (id) => {
    const { view } = useClusterView()
    const i = Number(id)
    if (!view) return { title: `Shard ${id}`, body: null, loading: true }
    if (!(i >= 0 && i < view.table.length)) return { title: `Shard ${id}`, body: null, missing: 'No shard at that position in the current layout.' }
    const o = view.table[i]
    const r = view.raw.layout?.shards[i]
    const owner = view.nodes.find((n) => n.node === o)
    return {
      title: <span className="mono">shard {r ? r.id : i}</span>,
      chip: o ? <Chip k="ok">owned</Chip> : <Chip k="err">unowned</Chip>,
      foot: <Src>getClusterStatus · table + layout</Src>,
      body: (
        <>
          <Strip items={[['owner', o ? o.replace(/^vlpds-/, '') : '—'], ['position', String(i)], ['layout version', view.raw.layout ? String(view.raw.layout.version) : '—']]} />
          <Sec title="Placement" digest={o ?? 'nobody'} open>
            <KV
              rows={[
                ['Owner', owner ? <button type="button" className="cx-linklike" onClick={() => openPanel('node', owner.node)}><NodeTag n={owner} /></button> : <Chip k="err">none: writes get 503</Chip>],
                ['Shard id', <span className="mono">{r ? r.id : i}</span>],
                ['Hash slots', r ? <span className="mono">{r.lo}–{r.hi - 1} ({fmtNum(r.hi - r.lo)} slots)</span> : 'all (single node)'],
                ['State', <span className="mono">state/{String(r ? r.id : i).padStart(10, '0')}/</span>],
              ]}
            />
          </Sec>
        </>
      ),
    }
  },
})

registerDetail('event', {
  kind: 'Firehose event',
  section: 'firehose',
  use: (seq) => {
    useFirehose()
    const { view } = useClusterView()
    const e = findEvent(seq)
    const handle = useHandle(e?.did)
    if (!e) return { title: <span className="mono">…{seq.slice(-10)}</span>, body: null, missing: 'This event scrolled out of the console’s buffer (the last 600 events since the page opened).' }
    const w = seqWriter(e.seq)
    const node = view?.single ? view.self : view?.nodes.find((n) => n.writer === w)?.node
    const ms = seqMillis(e.seq)
    return {
      title: (
        <>
          #{e.kind} <span className="muted mono sm">…{e.seq.slice(-10)}</span>
        </>
      ),
      chip: <Chip k="plain">{e.ops.length ? plural(e.ops.length, 'op') : e.kind}</Chip>,
      foot: <Src>com.atproto.sync.subscribeRepos</Src>,
      body: (
        <>
          <Strip items={[['kind', `#${e.kind}`], ['node', node?.replace(/^vlpds-/, '') ?? '—'], ['frame', fmtBytes(e.frameBytes)], ['received', clock(e.at)]]} />
          <Sec title="Seq" digest={e.seq} open>
            <KV
              rows={[
                ['seq', <Copy text={e.seq} />],
                ['assigned at', ms ? <span className="mono">{new Date(ms).toISOString()}</span> : '—'],
                ['writer byte', <>{w ?? '—'}{node && <> → <span className="mono">{node}</span></>}</>],
                ['event time', e.time ?? '—'],
              ]}
            />
          </Sec>
          <Sec title="Repo" digest={handle ? `@${handle}` : e.did} open>
            <KV
              rows={[
                ['account', <button type="button" className="cx-linklike" onClick={() => openPanel('account', e.did)}>{handle ? `@${handle}` : e.did}</button>],
                ['DID', <Copy text={e.did} />],
                ...(e.rev ? [['rev', <span className="mono">{e.rev}</span>] as [string, React.ReactNode]] : []),
                ...(e.commit ? [['commit', <Copy text={e.commit} />] as [string, React.ReactNode]] : []),
              ]}
            />
          </Sec>
          {e.ops.length > 0 && (
            <Sec title="Ops" digest={plural(e.ops.length, 'op')} open flush>
              <div className="cx-tw">
                <table className="cx-t compact">
                  <tbody>
                    {e.ops.map((o, i) => (
                      <tr key={i}>
                        <td className={`mono sm ${o.action === 'create' ? 'op-c' : o.action === 'update' ? 'op-u' : 'op-d'}`}>{o.action}</td>
                        <td className="mono sm">{o.path}</td>
                        <td className="mono sm muted">{o.cid ? `${o.cid.slice(0, 18)}…` : ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Sec>
          )}
          <Sec title="Frame" digest="the body as subscribers get it (blocks elided)" open>
            <Json value={e.body} />
          </Sec>
        </>
      ),
    }
  },
})

registerDetail('sub', {
  kind: 'Firehose connection',
  section: 'firehose',
  use: (id) => {
    const subs = subscribersPoll.use()
    const m = useMetrics()
    const [node, conn] = id.split('/')
    const s = subs.data?.subscribers.find((x) => x.node === node && x.conn === conn)
    const gone = subs.data?.recentDisconnects.find((x) => x.node === node && x.conn === conn)
    const x = s ?? gone
    if (!subs.data) return { title: `#${conn}`, body: null, loading: true }
    if (!x) return { title: <span className="mono">#{conn}</span>, body: null, missing: 'This connection is gone and has dropped out of the recent-disconnects list.' }
    const pdsRate = last(m.cluster, 'fhEvents')
    const lag = x.lagMs != null ? (x.lagMs < 1000 ? 'caught up' : `${dur(x.lagMs)} behind`) : x.lagEvents != null ? (x.lagEvents ? `${fmtNum(x.lagEvents)} events` : 'caught up') : '—'
    const as = x.asn != null ? `AS${x.asn}${x.asName ? ` ${x.asName}` : ''}${x.asCountry ? ` (${x.asCountry})` : ''}` : '—'
    return {
      title: (
        <>
          <span className="mono">#{x.conn}</span> <span className="muted">on</span> <span className="mono">{x.node}</span>
        </>
      ),
      chip: gone && !s ? <Chip k="idle">disconnected</Chip> : isSlow(x) ? <Chip k="warn">slow</Chip> : x.state === 'live' ? <Chip k="ok">live</Chip> : <Chip k="info">backfilling</Chip>,
      foot: <Src>vlpds.admin.listFirehoseSubscribers · 5 s</Src>,
      body: (
        <>
          <Strip items={[['state', gone && !s ? (x.reason ?? 'gone') : x.state], ['lag', lag], ['events sent', fmtNum(x.events)], ['bytes sent', fmtBytes(x.bytes)], ['connected', dur((x.disconnectedAt ?? Date.now()) - x.connectedAt)]]} />
          <Sec title="Client" digest={x.ip ?? 'unknown address'} open>
            <KV
              rows={[
                ['Address', <>{x.ip ? <Copy text={x.ip} /> : '—'} {x.relay && <Chip k="acc">{x.relay}</Chip>}</>],
                ['Network', as],
                ['Reverse DNS', x.ptr ? <>{x.ptr} {x.ptrVerified ? <Chip k="ok">verified</Chip> : <Chip k="warn">unverified</Chip>}</> : '—'],
                ['User agent', x.userAgent ? <span className="mono sm">{x.userAgent}</span> : '—'],
                ['Cursor', x.cursor ?? 'none (live tail)'],
                ['Unsent', x.lagBytes ? fmtBytes(x.lagBytes) : '—'],
                ['Metrics label', <span className="mono sm">vlpds_firehose_subscriber_events_total{`{conn="${x.labelled ? x.conn : 'other'}"}`}</span>],
                ...(x.reason ? [['Left because', <span className="mono">{x.reason}</span>] as [string, React.ReactNode]] : []),
              ]}
            />
          </Sec>
          {pdsRate !== undefined && <p className="muted sm" style={{ margin: 0 }}>This PDS emits {fmtSi(pdsRate)} events/s; a caught-up live subscriber gets the same.</p>}
          {s && (
            <Sec title="Actions" open flush>
              <div className="cx-acts">
                <div className="cx-act">
                  <div className="ad">
                    <b>Disconnect</b>Closes the socket with reason “kicked”. The client can reconnect with its cursor.
                  </div>
                  <button
                    type="button"
                    className="cx-btn sm danger"
                    onClick={() =>
                      confirmAction({
                        tone: 'warn',
                        title: `Disconnect #${s.conn} on ${s.node}?`,
                        items: ['Closes the websocket with reason “kicked”.', 'The client can reconnect with its cursor and backfill what it missed.'],
                        word: `#${s.conn}`,
                        action: 'Disconnect',
                        call: `vlpds.admin.kickSubscriber {"conn": "${s.conn}"} → ${s.node}`,
                        run: async () => {
                          const r = await kickSubscriber(s.node, s.conn)
                          if (!r.supported) throw new Error(`This server has no ${r.nsid} yet: update vlpds to disconnect subscribers from the console.`)
                          subscribersPoll.refresh()
                        },
                        done: `Disconnected #${s.conn}`,
                      })
                    }
                  >
                    Disconnect…
                  </button>
                </div>
              </div>
            </Sec>
          )}
        </>
      ),
    }
  },
})
