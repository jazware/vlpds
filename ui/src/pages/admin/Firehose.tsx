import { useState } from 'react'
import type { Col } from '../../components/console/DataTable'
import { DataTable } from '../../components/console/DataTable'
import { FormDialog, openDialog } from '../../components/console/dialogs'
import { Banners, Chip, ErrorState, Loading, PageHead, Panel, Sec, Spark, Src, Swatch, Tiles, type BannerSpec } from '../../components/console/kit'
import { LiveTail } from '../../components/console/LiveTail'
import { openPanel } from '../../components/console/nav'
import { registerPalette } from '../../components/console/Palette'
import { toast } from '../../components/console/toast'
import { useClusterView } from '../../lib/console/cluster'
import { ago, dur, fmtBytes, fmtMs, fmtNum, fmtSi, plural, seqMillis, seqWriter } from '../../lib/console/fmt'
import { isSlow, isThisBrowser, subscribersQ, type Subscriber, type SubscriberList } from '../../lib/console/queries'
import { subscriberState } from '../../lib/console/status'
import { crawlersQ, maxLatest, requestCrawl, setCrawlers, subKey, useNodeMetrics, useSubRates, worstSeries, type CrawlResult, type Relay } from '../../lib/console/sys'

// Firehose & relays: every subscribeRepos connection on every node with its rate against the
// PDS's, the relays asked to crawl, recent disconnects, and the merged live tail.

export const REASONS: Record<string, string> = {
  client_gone: 'Connection dropped',
  client_closed: 'Client closed it',
  too_slow: 'Too slow (fell behind)',
  write_stalled: 'Stopped reading',
  shutdown: 'Server shut down',
  kicked: 'Kicked from the console',
}
export const reasonText = (r?: string) => (r ? (REASONS[r] ?? r) : 'gone')

const shortNode = (n: string) => n.replace(/^vlpds-/, '')
const lastOf = (xs?: number[]) => (xs?.length ? xs[xs.length - 1] : 0)

/** Asks relays to crawl and reports each answer as a toast. */
export async function crawlNow(relays: string[]) {
  try {
    const r = await requestCrawl(relays)
    const bad = r.results.filter((x) => !x.ok)
    if (!bad.length) toast(`Asked ${plural(r.results.length, 'relay')} to crawl: accepted`)
    else toast(bad.map((x: CrawlResult) => `${x.relay}: ${x.status ?? ''} ${x.error ?? 'refused'}`).join(' · '), { err: true, ms: 8000 })
  } catch (e) {
    toast(e instanceof Error ? e.message : String(e), { err: true })
  }
}

export function addRelayDialog() {
  openDialog((close) => <AddRelay close={close} />)
}
function AddRelay({ close }: { close: () => void }) {
  const [v, setV] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const list = crawlersQ.get().data?.relays.map((r) => r.relay) ?? []
  return (
    <FormDialog
      title="Add a relay"
      call={`vlpds.admin.setCrawlers {"relays": [… "${v.trim() || 'host'}"]}`}
      action="Add relay"
      busy={busy}
      disabled={!v.trim()}
      error={error}
      onCancel={close}
      onSubmit={async () => {
        setBusy(true)
        setError(undefined)
        try {
          await setCrawlers({ relays: [...list, v.trim()] })
          toast(`Added ${v.trim()}`)
          close()
        } catch (e) {
          setError(e)
        } finally {
          setBusy(false)
        }
      }}
    >
      <label className="cx-lbl" htmlFor="relay-host">
        A hostname (asked over https) or an http(s):// origin
      </label>
      <input id="relay-host" className="cx-inp mono" autoFocus autoComplete="off" spellCheck={false} placeholder="relay.example.com" value={v} onChange={(e) => setV(e.target.value)} />
      <p className="muted sm" style={{ margin: 0 }}>
        The list is stored in the bucket for the whole cluster and overrides <span className="mono">--crawlers</span>.
      </p>
    </FormDialog>
  )
}

export function intervalDialog() {
  openDialog((close) => <Interval close={close} />)
}
function Interval({ close }: { close: () => void }) {
  const d = crawlersQ.get().data
  const [v, setV] = useState(d ? String(d.intervalSecs / 60) : '20')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const secs = Math.round(Number(v) * 60)
  const ok = Number.isFinite(secs) && secs >= 1 && secs <= 7 * 24 * 3600
  const save = async (intervalSecs: number | null) => {
    setBusy(true)
    setError(undefined)
    try {
      await setCrawlers({ intervalSecs })
      toast(intervalSecs === null ? 'Back to --crawl-interval-secs' : `Crawl interval set to ${v} min`)
      close()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormDialog title="Minimum crawl interval" icon="◷" call={`vlpds.admin.setCrawlers {"intervalSecs": ${ok ? secs : '…'}}`} action="Save" busy={busy} disabled={!ok} error={error} onCancel={close} onSubmit={() => save(secs)}>
      <label className="cx-lbl" htmlFor="crawl-int">
        Minutes between requests to one relay
      </label>
      <div className="cx-form-row">
        <input id="crawl-int" className="cx-inp mono" inputMode="decimal" autoFocus value={v} onChange={(e) => setV(e.target.value)} />
        {d?.intervalSource === 'stored' && (
          <button type="button" className="cx-btn" disabled={busy} onClick={() => save(null)}>
            Use the flag ({d.flagIntervalSecs / 60} min)
          </button>
        )}
      </div>
      <p className="muted sm" style={{ margin: 0 }}>
        The reference PDS uses 20 minutes. Stored for the cluster; overrides <span className="mono">--crawl-interval-secs</span>.
      </p>
    </FormDialog>
  )
}

export function RelayResult({ r }: { r: Relay }) {
  const s = r.status
  if (!s) return <Chip k="idle">not asked yet</Chip>
  if (s.ok) return <Chip k="ok">accepted{s.httpStatus ? ` (${s.httpStatus})` : ''}</Chip>
  return <Chip k="err">{s.httpStatus ? `rejected (${s.httpStatus})` : 'unreachable'}</Chip>
}

/** A relay's socket: connected now (several: the one furthest behind), else its latest disconnect. */
export function relaySocket(relay: string, d?: SubscriberList): { live?: Subscriber; gone?: Subscriber } {
  const live = d?.subscribers.filter((s) => s.relay === relay).sort((a, b) => (b.lagMs ?? 0) - (a.lagMs ?? 0))[0]
  if (live) return { live }
  const gone = d?.recentDisconnects.filter((s) => s.relay === relay).sort((a, b) => (b.disconnectedAt ?? 0) - (a.disconnectedAt ?? 0))[0]
  return { gone }
}

/** "● #41 live · caught up", "◆ #45 backfilling · 6h behind", "○ not connected · left 2d ago, too slow". */
export function RelaySubscribed({ relay, d }: { relay: string; d?: SubscriberList }) {
  if (!d) return <span className="muted">…</span>
  const { live, gone } = relaySocket(relay, d)
  if (live) {
    const lag = live.state === 'backfilling' ? (live.lagMs != null ? `${dur(live.lagMs)} behind` : 'backfilling') : isSlow(live) ? `${dur(live.lagMs ?? 0)} behind` : 'caught up'
    return (
      <button type="button" className="cxp-link" onClick={() => openPanel('sub', subKey(live))} title={`${live.node}, connected ${dur(Date.now() - live.connectedAt)}`}>
        <Chip k={live.state === 'backfilling' ? 'info' : isSlow(live) ? 'warn' : 'ok'}>
          #{live.conn} {live.state === 'backfilling' ? 'backfilling' : 'live'} · {lag}
        </Chip>
      </button>
    )
  }
  if (gone)
    return (
      <button type="button" className="cxp-link" onClick={() => openPanel('sub', subKey(gone))}>
        <Chip k="idle">
          not connected · left {gone.disconnectedAt ? ago(gone.disconnectedAt) : ''}, {reasonText(gone.reason).toLowerCase()}
        </Chip>
      </button>
    )
  return <Chip k="idle">not connected</Chip>
}

registerPalette({
  items: () => {
    const out = [
      { group: 'Actions', title: 'Request a crawl from every relay', desc: 'requestCrawl', glyph: '↻', run: () => crawlNow([]) },
      { group: 'Actions', title: 'Add a relay…', desc: 'setCrawlers', glyph: '+', run: addRelayDialog },
    ]
    const subs = subscribersQ.get().data?.subscribers ?? []
    const relays = crawlersQ.get().data?.relays ?? []
    return [
      ...out,
      ...relays.map((r) => ({ group: 'Firehose', title: `Relay ${r.relay}`, desc: r.status ? (r.status.ok ? 'accepted' : 'rejected') : 'not asked', glyph: '⇄', run: () => openPanel('relay', r.relay) })),
      ...subs.map((s) => ({
        group: 'Firehose',
        title: `#${s.conn} on ${s.node}`,
        desc: s.relay ?? s.ip ?? s.userAgent.slice(0, 40),
        hay: `${s.ip ?? ''} ${s.ptr ?? ''} ${s.userAgent}`,
        glyph: '≋',
        run: () => openPanel('sub', subKey(s)),
      })),
    ]
  },
})

function lagText(s: Subscriber) {
  if (s.state === 'backfilling') return <span className="s-info">◆ {s.lagMs != null ? `${dur(s.lagMs)} behind` : s.lagEvents != null ? `${fmtNum(s.lagEvents)} events` : 'backfilling'}</span>
  if (s.lagMs != null && s.lagMs >= 1000) return isSlow(s) ? <span className="s-warn">▲ {dur(s.lagMs)} behind</span> : <span>{dur(s.lagMs)} behind</span>
  if (s.lagEvents) return <span>{fmtNum(s.lagEvents)} events</span>
  return <span className="muted">caught up</span>
}

function stateChip(s: Subscriber) {
  const [k, t] = subscriberState(s, isSlow(s))
  return <Chip k={k}>{t}</Chip>
}

export function Firehose() {
  const { view } = useClusterView()
  const { subs, rates } = useSubRates()
  const m = useNodeMetrics()
  const cr = crawlersQ.use()
  const d = subs.data
  const color = (node: string) => view?.nodes.find((n) => n.node === node)?.color
  // the node-metrics poll has the rate from its first answer; two subscriber polls take 10 s
  const fhSeries = worstSeries(m.nodes, 'firehoseEventsPerSec')
  const pdsNow = maxLatest(m.nodes, 'firehoseEventsPerSec') ?? rates.pds[rates.pds.length - 1]
  const seq = view?.raw.firehose.lastEmitted
  const sms = seqMillis(seq)
  const w = seqWriter(seq)
  const writer = view?.single ? view.self : view?.nodes.find((n) => n.writer === w)?.node
  const emit = maxLatest(m.nodes, 'emitP99Ms')
  const slow = d?.subscribers.filter(isSlow) ?? []
  const failing = cr.data?.relays.filter((r) => r.status && !r.status.ok) ?? []

  const banners: BannerSpec[] = []
  if (d?.unreachableNodes?.length)
    banners.push({ id: 'unreach', tone: 'warn', title: `${plural(d.unreachableNodes.length, 'node')} didn't answer`, desc: `Not listed: the subscribers of ${d.unreachableNodes.join(', ')}.` })
  if (slow.length)
    banners.push({
      id: 'slow',
      tone: 'warn',
      title: `${plural(slow.length, 'live subscriber')} more than 30 s behind`,
      desc: 'Past --firehose-max-lag-mb unsent it gets ConsumerTooSlow and is dropped.',
      right: slow.map((s) => `#${s.conn}`).join(' '),
    })
  if (failing.length)
    banners.push({ id: 'relays', tone: 'warn', title: `${plural(failing.length, 'relay')} refused the last crawl request`, desc: failing.map((r) => r.relay).join(', ') })

  const cols: Col<Subscriber>[] = [
    {
      id: 'conn',
      label: 'Conn',
      sort: (a, b) => a.connectedAt - b.connectedAt,
      render: (s) => (
        <span className="cx-cellid">
          <Swatch color={color(s.node)} title={s.node} />
          <span className="mono">#{s.conn}</span>
          <span className="muted mono sm">{shortNode(s.node)}</span>
        </span>
      ),
    },
    {
      id: 'client',
      label: 'Client',
      render: (s) => (
        <span className="cx-cellid">
          <span className="mono">{s.ip ?? '—'}</span>
          {s.relay ? <Chip k="acc">{s.relay}</Chip> : isThisBrowser(s) ? <span className="muted sm">this browser</span> : null}
        </span>
      ),
    },
    {
      id: 'net',
      label: 'Network',
      render: (s) =>
        s.asn != null ? (
          <span className="t2 trunc" style={{ maxWidth: 200, display: 'inline-block', verticalAlign: 'middle' }} title={`AS${s.asn} ${s.asName ?? ''}`}>
            <span className="mono">AS{s.asn}</span> {s.asName}
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    { id: 'state', label: 'State', sort: (a, b) => (a.state === b.state ? 0 : a.state === 'live' ? 1 : -1), render: stateChip },
    { id: 'lag', label: 'Lag', r: true, sort: (a, b) => (a.lagMs ?? 0) - (b.lagMs ?? 0), render: lagText },
    {
      id: 'rate',
      label: 'Events/s vs PDS',
      title: 'This connection (solid) against what the PDS emits (dashed)',
      sort: (a, b) => lastOf(rates.conns.get(subKey(a))) - lastOf(rates.conns.get(subKey(b))),
      render: (s) => {
        const h = rates.conns.get(subKey(s)) ?? []
        const v = h[h.length - 1]
        return (
          <span className="cx-cellid">
            {h.length < 2 ? <span className="muted sm" style={{ width: 72, display: 'inline-block' }}>measuring…</span> : <Spark size="inline" data={h} l2={rates.pds.slice(-h.length)} color={isSlow(s) ? 'warn' : s.state === 'backfilling' ? 'info' : 'accent'} />}
            <span className="mono sm">{v === undefined ? '—' : fmtSi(v)}</span>
          </span>
        )
      },
    },
    { id: 'since', label: 'Connected', r: true, sort: (a, b) => b.connectedAt - a.connectedAt, render: (s) => dur(Date.now() - s.connectedAt) },
    { id: 'cursor', label: 'Cursor', render: (s) => (s.cursor ? <span className="mono sm">{s.cursor}</span> : <span className="muted">none</span>) },
    {
      id: 'ua',
      label: 'User agent',
      render: (s) => (
        <span className="t2 sm trunc" style={{ maxWidth: 200, display: 'inline-block', verticalAlign: 'middle' }} title={s.userAgent}>
          {s.userAgent || '—'}
        </span>
      ),
    },
    { id: 'sent', label: 'Sent', r: true, sort: (a, b) => a.bytes - b.bytes, render: (s) => <span className="mono">{fmtBytes(s.bytes)}</span> },
  ]

  const discCols: Col<Subscriber>[] = [
    {
      id: 'conn',
      label: 'Conn',
      render: (s) => (
        <span className="cx-cellid">
          <Swatch color={color(s.node)} title={s.node} />
          <span className="mono">#{s.conn}</span>
          <span className="muted mono sm">{shortNode(s.node)}</span>
        </span>
      ),
    },
    { id: 'client', label: 'Client', render: (s) => <span className="mono">{s.relay ?? s.ip ?? '—'}</span> },
    { id: 'reason', label: 'Reason', render: (s) => (s.reason === 'too_slow' ? <Chip k="err">{reasonText(s.reason)}</Chip> : s.reason === 'kicked' ? <Chip k="warn">{reasonText(s.reason)}</Chip> : <Chip k="idle">{reasonText(s.reason)}</Chip>) },
    { id: 'left', label: 'Left', r: true, sort: (a, b) => (a.disconnectedAt ?? 0) - (b.disconnectedAt ?? 0), render: (s) => (s.disconnectedAt ? ago(s.disconnectedAt) : '—') },
    { id: 'stayed', label: 'Stayed', r: true, render: (s) => dur((s.disconnectedAt ?? Date.now()) - s.connectedAt) },
    { id: 'events', label: 'Events', r: true, render: (s) => <span className="mono">{fmtNum(s.events)}</span> },
  ]

  const disc = d ? [...d.recentDisconnects].sort((a, b) => (b.disconnectedAt ?? 0) - (a.disconnectedAt ?? 0)) : []
  const tooSlow = disc.filter((x) => x.reason === 'too_slow').length
  const nodesWithSubs = d ? new Set(d.subscribers.map((s) => s.node)).size : 0

  return (
    <>
      <PageHead
        title="Firehose & relays"
        sub={
          <>
            <span>{d ? `${plural(d.total, 'subscriber')} on ${plural(Math.max(nodesWithSubs, d.nodes.length), 'node')}` : '…'}</span>
            <span>merged by watermark, no global sequencer</span>
            {cr.data && <span>relays told about {cr.data.hostname}</span>}
          </>
        }
        updated={subs.at}
        actions={
          <button type="button" className="cx-btn" disabled={!cr.data?.relays.length} onClick={() => crawlNow([])} title="com.atproto.sync.requestCrawl to every relay">
            Request crawl from all
          </button>
        }
      />
      <Banners items={banners} />
      <Tiles
        boxed
        tiles={[
          {
            label: 'Last emitted seq',
            right: sms ? `writer ${w}${writer ? ` · ${shortNode(writer)}` : ''}` : undefined,
            value: <span className="mono" style={{ fontSize: 15 }}>{seq && seq !== '0' ? seq : '—'}</span>,
            title: 'unix µs × 256 + the writer byte of the log that assigned it',
          },
          {
            label: "This PDS's events / s",
            right: 'every node emits the whole stream',
            value: pdsNow === undefined ? '—' : fmtSi(pdsNow),
            spark: <Spark data={fhSeries.length ? fhSeries : rates.pds} color="accent" />,
          },
          {
            label: 'Subscribers',
            right: d ? `${fmtNum(d.live)} live · ${fmtNum(d.backfilling)} backfilling` : undefined,
            value: d ? fmtNum(d.total) : '—',
            sec: slow.length ? `${slow.length} slow` : undefined,
          },
          {
            label: 'Sent to subscribers',
            right: 'all nodes',
            value: rates.sent.length ? `${fmtBytes(rates.sent[rates.sent.length - 1])}/s` : '—',
            spark: <Spark data={rates.sent} color="c2" />,
          },
          {
            label: 'Emit delay p99',
            right: 'worst node · alert at 2 s',
            value: m.status === 'unsupported' ? '—' : fmtMs(emit),
            spark: <Spark data={worstSeries(m.nodes, 'emitP99Ms')} color="violet" th={2000} />,
          },
        ]}
      />
      <Panel
        className="cx-mt"
        title="Connected"
        src={<Src>vlpds.admin.listFirehoseSubscribers · on change</Src>}
        right={<span className="muted sm">{d && d.total > d.subscribers.length ? `first ${fmtNum(d.subscribers.length)} of ${fmtNum(d.total)} · ` : ''}oldest first</span>}
      >
        {d ? (
          <DataTable
            rows={d.subscribers}
            cols={cols}
            rowKey={subKey}
            open={(s) => ({ type: 'sub', id: subKey(s) })}
            empty={<div className="cx-empty">No one is subscribed to this PDS right now.</div>}
            label="Firehose subscribers"
          />
        ) : subs.error ? (
          <ErrorState error={subs.error} retry={subscribersQ.refresh} />
        ) : (
          <Loading />
        )}
      </Panel>
      <div className="cx-grid2 cx-mt">
        <div className="cx-stack">
          <Panel
            title="Relays"
            src={<Src>getCrawlers · setCrawlers · requestCrawl</Src>}
            right={
              cr.data && (
                <>
                  <button type="button" className="cx-btn sm quiet" onClick={intervalDialog} title="Change the minimum interval">
                    every ≥ {cr.data.intervalSecs % 60 ? `${cr.data.intervalSecs} s` : `${cr.data.intervalSecs / 60} min`}
                  </button>
                  <button type="button" className="cx-btn sm" onClick={addRelayDialog}>
                    Add relay…
                  </button>
                </>
              )
            }
            foot={
              cr.data && (
                <span>
                  Sent by the owner of slot 0 ({cr.data.sender ? 'this node, ' : ''}
                  <span className="mono">{cr.data.node}</span>).{' '}
                  {cr.data.relaysSource === 'stored' ? (
                    <>
                      Stored in the bucket; overrides <span className="mono">--crawlers</span>
                      {cr.data.updatedAt ? `, changed ${ago(Date.parse(cr.data.updatedAt))}` : ''}.{' '}
                      <button
                        type="button"
                        className="cx-linklike"
                        onClick={async () => {
                          try {
                            await setCrawlers({ relays: null })
                            toast('Back to --crawlers')
                          } catch (e) {
                            toast(e instanceof Error ? e.message : String(e), { err: true })
                          }
                        }}
                      >
                        Use --crawlers ({cr.data.flagRelays.join(', ') || 'none'})
                      </button>
                    </>
                  ) : (
                    <>
                      From <span className="mono">--crawlers</span>. Changing the list here stores it for the cluster.
                    </>
                  )}
                </span>
              )
            }
          >
            {cr.data ? (
              <DataTable
                compact
                rows={cr.data.relays}
                rowKey={(r) => r.relay}
                open={(r) => ({ type: 'relay', id: r.relay })}
                empty={<div className="cx-empty">No relays: nothing is told about this PDS until one is added.</div>}
                cols={[
                  { id: 'relay', label: 'Relay', render: (r) => <span className="mono">{r.relay}</span> },
                  { id: 'res', label: 'Last result', render: (r) => <RelayResult r={r} /> },
                  { id: 'asked', label: 'Asked', render: (r) => (r.status ? ago(r.status.lastAttemptMs) : <span className="muted">—</span>) },
                  { id: 'ok', label: 'Accepted', render: (r) => (r.status?.lastSuccessMs ? ago(r.status.lastSuccessMs) : <span className="muted">—</span>) },
                  { id: 'sub', label: 'Subscribed', title: 'Its subscribeRepos socket now, from the subscriber list', render: (r) => <RelaySubscribed relay={r.relay} d={d} /> },
                  {
                    id: 'act',
                    label: '',
                    r: true,
                    render: (r) => (
                      <button type="button" className="cx-btn sm quiet" onClick={() => crawlNow([r.relay])} title="Crawl now: requestCrawl to this relay">
                        Crawl
                      </button>
                    ),
                  },
                ]}
              />
            ) : cr.error ? (
              <ErrorState error={cr.error} retry={crawlersQ.refresh} />
            ) : (
              <Loading />
            )}
          </Panel>
          <Sec title="Recently disconnected" digest={d ? `${disc.length} kept${tooSlow ? ` · ${tooSlow} too slow` : ''}` : ''} open flush>
            {d ? (
              <DataTable rows={disc} cols={discCols} rowKey={(s) => `${subKey(s)}@${s.disconnectedAt}`} open={(s) => ({ type: 'sub', id: subKey(s) })} compact empty={<div className="cx-empty">Nobody has left since the nodes started.</div>} />
            ) : (
              <Loading />
            )}
          </Sec>
        </div>
        <Panel title="Live events">
          <LiveTail height={420} max={200} nodeFilter />
        </Panel>
      </div>
    </>
  )
}
