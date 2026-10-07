import { Banners, ErrorState, Glyph, HealthLine, Kbd, Loading, Meter, Mini, Minis, NeedsVersion, Panel, RRow, Spark, Src, Tiles, type HealthCell, type Tone } from '../../components/console/kit'
import { LiveTail } from '../../components/console/LiveTail'
import { openPanel } from '../../components/console/nav'
import { SECTION } from '../../components/console/sections'
import { Strata } from '../../components/console/Strata'
import { clusterPoll, useClusterView, type ClusterView } from '../../lib/console/cluster'
import { ago, dur, factorName, fmtBytes, fmtMs, fmtNum, fmtSec, fmtSi, seqMillis, seqWriter } from '../../lib/console/fmt'
import { col, last, useMetrics, type MetricsState } from '../../lib/console/metrics'
import { segmentsPoll } from '../../lib/console/segments'
import { auditPoll, isSlow, isThisBrowser, lockoutsPoll, openCasesPoll, subscribersPoll, type SubscriberList } from '../../lib/console/polls'
import { clusterBanners, NodesTable } from './clusterUi'

// The overview: what's wrong (banners), one health line across every subsystem, the write
// path, the logs merging into the firehose, the nodes, live events, and a rail of the queues.

const P = SECTION

const n1 = (v: number | undefined) => (v === undefined ? '—' : fmtSi(v))
const ms = (s: number | undefined) => fmtSec(s)

function health(view: ClusterView, m: MetricsState, subs?: SubscriberList): HealthCell[] {
  const c = m.cluster
  const v = view.raw.version
  const noM = m.source === 'none'
  const down = view.nodes.filter((n) => n.health === 'err')
  const p99 = last(c, 'durP99')
  const fh = last(c, 'fhEvents')
  const slow = subs?.subscribers.filter(isSlow).length ?? 0
  const errs = last(c, 'objErr') ?? 0
  const limited = last(c, 'limited')
  const gs = Object.values(m.gauges)
  const sumG = (k: 'mailQueue' | 'mailBudgetRemaining' | 'mailBudgetLimit') => (gs.some((g) => g[k] !== undefined) ? gs.reduce((a, g) => a + (g[k] ?? 0), 0) : undefined)
  const mailQ = sumG('mailQueue')
  const budget = gs.find((g) => g.mailBudgetLimit !== undefined)
  const wm = view.wmLagMs
  const tone = (bad: boolean, worse = false): Tone => (worse ? 'err' : bad ? 'warn' : 'ok')
  const nometric = 'no /metrics here'
  return [
    {
      label: 'Nodes',
      to: P.nodes.path,
      tone: view.single ? 'ok' : tone(false, down.length > 0),
      value: view.single ? '1' : view.leased,
      unit: view.single ? 'node' : `/${view.nodes.length} leased`,
      sub: view.single ? 'single node · no leases' : down.length ? `${down.map((n) => n.node).join(', ')} down` : 'all leases valid',
    },
    {
      label: 'Shards',
      to: P.nodes.path,
      tone: tone(false, view.unowned > 0),
      value: view.table.length - view.unowned,
      unit: `/${view.table.length} owned`,
      sub: view.unowned ? `${view.unowned} unowned: writes 503` : v ? `level ${v.active ?? '—'}${v.finalizable ? ` · ${v.finalizable} ready` : ''}` : 'every shard local',
    },
    {
      label: 'Commit → durable',
      to: P.nodes.path,
      tone: p99 === undefined ? 'idle' : tone(p99 > 0.5, p99 > 2),
      value: noM ? '—' : ms(p99),
      unit: 'p99',
      sub: noM ? nometric : `p50 ${ms(last(c, 'durP50'))}`,
    },
    {
      label: 'Firehose',
      to: P.firehose.path,
      tone: tone(slow > 0, wm !== undefined && wm > 10_000),
      value: noM ? '—' : n1(fh),
      unit: 'ev/s',
      sub: `watermark ${fmtMs(wm)} · ${subs ? `${subs.total} subs` : '…'}`,
    },
    {
      label: 'Object store',
      to: P.storage.path,
      tone: noM ? 'idle' : tone(errs > 0),
      value: noM ? '—' : n1(last(c, 'objA')),
      unit: 'A/s',
      sub: noM ? nometric : `B ${n1(last(c, 'objB'))}/s · ${errs > 0 ? `${fmtSi(errs)} errors/s` : 'no errors'}`,
    },
    ...moderationCell(),
    {
      label: 'Rate limits',
      to: P.limits.path,
      tone: limited === undefined ? 'idle' : tone(limited * 60 > 10),
      value: limited === undefined ? '—' : fmtNum(Math.round(limited * 60)),
      unit: '429s/min',
      sub: lockSub(),
    },
    {
      label: 'Mail',
      to: P.mail.path,
      tone: budget?.mailBudgetLimit && budget.mailBudgetRemaining !== undefined ? tone(budget.mailBudgetRemaining < budget.mailBudgetLimit * 0.1) : noM ? 'idle' : 'ok',
      value: noM ? '—' : fmtNum(mailQ ?? 0),
      unit: 'queued',
      sub:
        budget?.mailBudgetLimit !== undefined && budget.mailBudgetRemaining !== undefined
          ? `${fmtNum(budget.mailBudgetLimit - budget.mailBudgetRemaining)} / ${fmtNum(budget.mailBudgetLimit)} sent today`
          : noM
            ? nometric
            : 'no daily budget',
    },
  ]
}

function moderationCell(): HealthCell[] {
  const cases = openCasesPoll.get()
  const list = cases.data
  const oldest = list?.length ? Math.min(...list.map((c) => Date.parse(c.createdAt))) : undefined
  return [
    {
      label: 'Moderation',
      to: P.moderation.path,
      tone: list === undefined ? 'idle' : list.length ? 'warn' : 'ok',
      value: list === undefined ? '—' : list.length,
      unit: 'open cases',
      sub: oldest ? `oldest ${ago(oldest).replace(' ago', '')}` : list ? 'queue empty' : '…',
    },
  ]
}

function lockSub(): string {
  const l = lockoutsPoll.get().data
  if (!l) return '…'
  if (!l.supported) return 'lockouts need a newer vlpds'
  const a = new Set(l.data.map((x) => x.did)).size
  return a ? `${a} accounts locked out` : 'nobody locked out'
}

function WritePath({ m }: { m: MetricsState }) {
  const c = m.cluster
  if (m.source === 'none')
    return (
      <>
        <NeedsVersion what="Write-path metrics" nsid="vlpds.admin.getNodeMetrics" />
        <div className="cx-pn-f">This node keeps /metrics off the app port (--metrics-listen), so the console can't scrape it directly.</div>
      </>
    )
  const http = last(c, 'http')
  const e5 = last(c, 'http5xx')
  const cached = Object.values(m.gauges).reduce((a, g) => a + (g.cachedRepos ?? 0), 0)
  return (
    <Tiles
      tiles={[
        { label: 'Commits / s', right: `ops/s ${n1(last(c, 'ops'))}`, value: n1(last(c, 'commits')), spark: <Spark data={col(c, 'commits')} color="accent" />, to: P.nodes.path },
        { label: 'Commit → durable', right: 'p99 · p50 dashed', value: ms(last(c, 'durP99')), sec: `p50 ${ms(last(c, 'durP50'))}`, spark: <Spark data={col(c, 'durP99')} l2={col(c, 'durP50')} color="amber" th={0.5} /> },
        { label: 'Segment PUT', right: last(c, 'hedges') === undefined ? 'p99 · p50 dashed' : `hedges ${n1(last(c, 'hedges'))}/s`, value: ms(last(c, 'putP99')), sec: `p50 ${ms(last(c, 'putP50'))}`, spark: <Spark data={col(c, 'putP99')} l2={col(c, 'putP50')} color="amber" />, to: P.storage.path },
        { label: 'HTTP requests / s', right: `5xx ${http ? `${(((e5 ?? 0) / http) * 100).toFixed(2)}%` : '—'}`, value: n1(http), spark: <Spark data={col(c, 'http')} color="c2" /> },
        { label: 'Firehose emit delay', right: 'p99', value: ms(last(c, 'emitP99')), spark: <Spark data={col(c, 'emitP99')} color="violet" th={2} />, to: P.firehose.path },
        { label: 'Cold repo loads / s', right: `${fmtNum(cached)} in memory`, value: n1(last(c, 'loads')), spark: <Spark data={col(c, 'loads')} color="c6" /> },
      ]}
    />
  )
}

function Rail({ view, m, subs }: { view: ClusterView; m: MetricsState; subs?: SubscriberList }) {
  const c = m.cluster
  const cases = openCasesPoll.use()
  const audit = auditPoll.use()
  const locks = lockoutsPoll.use()
  const seq = view.raw.firehose.lastEmitted
  const w = seqWriter(seq)
  const writer = view.single ? view.self : view.nodes.find((n) => n.writer === w)?.node
  const sms = seqMillis(seq)
  const budget = Object.values(m.gauges).find((g) => g.mailBudgetLimit !== undefined)
  const mailQ = Object.values(m.gauges).reduce((a, g) => a + (g.mailQueue ?? 0), 0)
  return (
    <aside className="cx-rail cx-stack">
      <Panel title="Firehose" to={P.firehose.path} src={<Src>getClusterStatus · listFirehoseSubscribers</Src>}>
        <div className="cx-seqbox">
          <div className="cx-eyebrow">last emitted seq</div>
          <div className="cx-seqv">{seq === '0' ? '—' : seq}</div>
          <div className="cx-seqd">{sms ? `${new Date(sms).toISOString().slice(11, 23)}Z · writer ${w}${writer ? ` (${writer})` : ''}` : 'nothing emitted yet'}</div>
        </div>
        {m.source !== 'none' && (
          <Minis>
            <Mini label="events/s" value={n1(last(c, 'fhEvents'))}>
              <Spark data={col(c, 'fhEvents')} color="accent" />
            </Mini>
            <Mini label="sent" value={last(c, 'fhBytes') !== undefined ? `${fmtBytes(last(c, 'fhBytes')!)}/s` : '—'}>
              <Spark data={col(c, 'fhBytes')} color="c2" />
            </Mini>
          </Minis>
        )}
        {subs?.subscribers.slice(0, 5).map((s) => (
          <RRow key={`${s.node}/${s.conn}`} onClick={() => openPanel('sub', `${s.node}/${s.conn}`)} x={s.state === 'backfilling' ? 'backfilling' : isSlow(s) ? `${dur(s.lagMs ?? 0)} behind` : 'caught up'}>
            <Glyph k={s.state === 'backfilling' ? 'info' : isSlow(s) ? 'warn' : 'ok'} />
            <span className="mono sm">#{s.conn}</span>
            <span className="nm">{s.relay ? <span className="cx-chip acc">{s.relay}</span> : isThisBrowser(s) ? <span className="muted">this browser’s live tail</span> : s.userAgent.split(' ')[0] || s.ip}</span>
          </RRow>
        ))}
        {subs && !subs.subscribers.length && <RRow x="">No subscribers right now</RRow>}
      </Panel>

      <Panel title="Object store" to={P.storage.path} src={<Src>/metrics · object_store_requests</Src>}>
        {m.source === 'none' ? (
          <NeedsVersion what="Request rates" nsid="vlpds.admin.getNodeMetrics" />
        ) : (
          <>
            <Minis>
              <Mini label="Class A /s" value={n1(last(c, 'objA'))}>
                <Spark data={col(c, 'objA')} color="c3" />
              </Mini>
              <Mini label="Class B /s" value={n1(last(c, 'objB'))}>
                <Spark data={col(c, 'objB')} color="c6" />
              </Mini>
            </Minis>
            <RRow x={<span className="mono">{n1(last(c, 'objErr') ?? 0)}/s</span>}>
              <span className="nm">Errors and timeouts</span>
            </RRow>
            {last(c, 'hedges') !== undefined && (
              <RRow x={<span className="mono">{n1(last(c, 'hedges'))}/s</span>}>
                <span className="nm">Hedged segment PUTs</span>
              </RRow>
            )}
          </>
        )}
      </Panel>

      <Panel title="Moderation queue" to={P.moderation.path} src={<Src>listCases</Src>} right={cases.data?.length ? <span className="cx-chip warn">▲ {cases.data.length} open</span> : undefined}>
        {cases.error ? (
          <ErrorState error={cases.error} />
        ) : !cases.data ? (
          <Loading />
        ) : cases.data.length ? (
          cases.data.slice(0, 6).map((k) => (
            <RRow key={k.id} to={`/admin/moderation/cases/${encodeURIComponent(k.id)}`} x={ago(Date.parse(k.createdAt))}>
              <Glyph k="warn" />
              <span className="mono sm">{k.id.slice(0, 10)}</span>
              <span className="nm">
                {k.subjects.map((s) => s.kind).join(' + ')} · {k.source}
              </span>
            </RRow>
          ))
        ) : (
          <RRow>
            <Glyph k="ok" />
            <span className="nm">No open cases</span>
          </RRow>
        )}
      </Panel>

      <Panel title="Limits & lockouts" to={P.limits.path} src={<Src isNew={!locks.data?.supported}>listLockouts</Src>}>
        {m.source !== 'none' && (
          <Minis n={1}>
            <Mini label="429s per second" value={n1(last(c, 'limited'))}>
              <Spark data={col(c, 'limited')} color="warn" />
            </Mini>
          </Minis>
        )}
        {locks.data && !locks.data.supported ? (
          <NeedsVersion what="Who is locked out" nsid={locks.data.nsid} />
        ) : (
          locks.data?.data.slice(0, 5).map((l, i) => (
            <RRow key={i} onClick={() => openPanel('account', l.did)} x={`${factorName(l.factor)} · clears in ${dur(l.lockedUntil - Date.now())}`}>
              <Glyph k="warn" />
              <span className="nm">{l.handle ? `@${l.handle}` : <span className="mono sm">{l.did}</span>}</span>
            </RRow>
          ))
        )}
        {locks.data?.supported && !locks.data.data.length && (
          <RRow>
            <Glyph k="ok" />
            <span className="nm">Nobody is locked out</span>
          </RRow>
        )}
      </Panel>

      <Panel title="Mail" to={P.mail.path} src={<Src>/metrics · vlpds_mail_*</Src>}>
        {m.source === 'none' ? (
          <NeedsVersion what="Mail queue and budget" nsid="vlpds.admin.getNodeMetrics" />
        ) : (
          <>
            {budget?.mailBudgetLimit !== undefined && budget.mailBudgetRemaining !== undefined ? (
              <RRow
                x={
                  <>
                    <Meter v={budget.mailBudgetLimit - budget.mailBudgetRemaining} max={budget.mailBudgetLimit} />{' '}
                    <span className="mono">
                      {fmtNum(budget.mailBudgetLimit - budget.mailBudgetRemaining)} / {fmtNum(budget.mailBudgetLimit)}
                    </span>
                  </>
                }
              >
                <span className="nm">Cluster budget today</span>
              </RRow>
            ) : (
              <RRow x="unset">
                <span className="nm">Cluster budget today</span>
              </RRow>
            )}
            <RRow x={<span className="mono">{fmtNum(mailQ)}</span>}>
              <span className="nm">Queued{m.source === 'fanout' ? ' (all nodes)' : ' (this node)'}</span>
            </RRow>
          </>
        )}
      </Panel>

      <Panel title="Operator activity" to={`${P.moderation.path}?tab=audit`} src={<Src>getAuditLog</Src>}>
        {audit.error ? (
          <ErrorState error={audit.error} />
        ) : !audit.data ? (
          <Loading />
        ) : audit.data.length ? (
          audit.data.slice(0, 5).map((e) => (
            <RRow key={e.id} to={`${P.moderation.path}?tab=audit`} x={ago(Date.parse(e.at))}>
              <span className="mono sm t2">{e.action}</span>
              <span className="nm muted">{e.subject?.uri ?? e.subject?.did ?? e.reason ?? ''}</span>
            </RRow>
          ))
        ) : (
          <RRow>
            <span className="nm muted">Nothing yet</span>
          </RRow>
        )}
      </Panel>
    </aside>
  )
}

export function Overview() {
  const { view, error, at } = useClusterView()
  const m = useMetrics()
  const subs = subscribersPoll.use()
  const locks = lockoutsPoll.use()
  const feed = segmentsPoll.use().data?.supported
  openCasesPoll.use()
  if (!view) return error ? <ErrorState error={error} retry={clusterPoll.refresh} /> : <Loading label="Asking the cluster…" />
  return (
    <>
      <Banners items={clusterBanners(view, subs.data, locks.data)} />
      <HealthLine cells={health(view, m, subs.data)} />
      <div className="cx-ov">
        <div className="cx-stack">
          <Panel title="Write path" src={<Src>{m.source === 'fanout' ? 'getNodeMetrics · every node' : '/metrics · this node'} · 2 s</Src>} right={<span className="muted sm">last 3 min{m.source === 'local' && !view.single ? ' · this node' : ''}</span>}>
            <WritePath m={m} />
          </Panel>
          <Panel
            title="Logs → watermark → firehose"
            src={<Src>{feed ? 'listSegments · getClusterStatus · 2 s' : 'getClusterStatus · durable ordinals'}</Src>}
            right={
              <span className="cx-legend">
                <span>
                  <i style={{ background: 'var(--amber)' }} />
                  min watermark
                </span>
                {feed && (
                  <span>
                    <i style={{ background: 'var(--ink3)' }} />
                    PUT in flight
                  </span>
                )}
              </span>
            }
          >
            <div className="cx-strata">
              <Strata view={view} fetchedAt={at} />
              <div className="lg">
                <span>
                  Each block is a log segment, a batch of commits written with one PUT{feed ? ', solid once durable' : ', placed from the durable ordinal between polls'}. The firehose emits
                  everything left of the amber line: the slowest log's watermark.
                </span>
              </div>
            </div>
          </Panel>
          <Panel
            title="Nodes"
            to={P.nodes.path}
            src={<Src>getClusterStatus · 2 s</Src>}
            right={
              <span className="muted sm">
                <Kbd k={['j', 'k']} /> move · <Kbd k="↵" /> open
              </span>
            }
          >
            <NodesTable view={view} metrics={m} compact />
          </Panel>
          <Panel title="Live events" to={P.firehose.path}>
            <LiveTail height={282} max={80} />
          </Panel>
        </div>
        <Rail view={view} m={m} subs={subs.data} />
      </div>
    </>
  )
}
