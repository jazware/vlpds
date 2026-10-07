import { Banners, ErrorState, Glyph, HealthLine, Kbd, Loading, NeedsVersion, Panel, RRow, Spark, Src, Tiles, type HealthCell, type Tone } from '../../components/console/kit'
import { LiveTail } from '../../components/console/LiveTail'
import { openPanel } from '../../components/console/nav'
import { SECTION } from '../../components/console/sections'
import { Strata } from '../../components/console/Strata'
import { clusterPoll, useClusterView, type ClusterView } from '../../lib/console/cluster'
import { ago, dur, factorName, fmtMs, fmtNum, fmtSec, fmtSi, plural } from '../../lib/console/fmt'
import { col, last, useMetrics, type MetricsState } from '../../lib/console/metrics'
import { useStartedAt } from '../../lib/console/nodeMetrics'
import { segmentsPoll } from '../../lib/console/segments'
import { auditPoll, isSlow, isThisBrowser, lockoutsPoll, openCasesPoll, subscribersPoll, type SubscriberList } from '../../lib/console/polls'
import { heldSignInKeys, rlPoll, shortName } from '../../lib/console/ratelimits'
import { crawlersPoll } from '../../lib/console/sys'
import { clusterBanners, NodesTable } from './clusterUi'

// The overview: what's wrong (banners), one health line across every subsystem, the write
// path, the logs merging into the firehose, the nodes, live events, and a rail that names
// what's waiting: subscribers, cases, who is locked out, relays, operator activity.

const P = SECTION

const n1 = (v: number | undefined) => (v === undefined ? '—' : fmtSi(v))
const ms = (s: number | undefined) => fmtSec(s)

/** "fe4e180 on 3/3 · youngest up 4m": did every node restart onto the build. */
function buildSub(view: ClusterView, started: Map<string, number>): string {
  const revs = new Map<string, number>()
  for (const n of view.nodes) if (n.rev) revs.set(n.rev, (revs.get(n.rev) ?? 0) + 1)
  if (!revs.size && view.raw.version) revs.set(view.raw.version.binary.rev, view.nodes.length)
  const [rev, on] = [...revs.entries()].sort((a, b) => b[1] - a[1])[0] ?? []
  // a cluster of one names its node differently in the status and the metrics
  const ups = view.nodes.length === 1 ? [...started.values()] : view.nodes.map((n) => started.get(n.node)).filter((t): t is number => !!t)
  const youngest = ups.length ? dur(Date.now() - Math.max(...ups)) : undefined
  const build = rev ? (view.single || view.nodes.length === 1 ? rev.slice(0, 7) : `${rev.slice(0, 7)} on ${on}/${view.nodes.length}`) : undefined
  return [build, youngest && (view.nodes.length > 1 ? `youngest up ${youngest}` : `up ${youngest}`)].filter(Boolean).join(' · ')
}

const pct5xx = (http?: number, e5?: number) => (http ? ((e5 ?? 0) / http) * 100 : undefined)

function health(view: ClusterView, m: MetricsState, started: Map<string, number>, subs?: SubscriberList): HealthCell[] {
  const c = m.cluster
  const noM = m.source === 'none'
  const down = view.nodes.filter((n) => n.health === 'err')
  const http = last(c, 'http')
  const p5 = pct5xx(http, last(c, 'http5xx'))
  const build = buildSub(view, started)
  const shards = `${view.table.length - view.unowned}/${view.table.length} shards`
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
      tone: view.single ? tone(false, view.unowned > 0) : tone(false, down.length > 0 || view.unowned > 0),
      value: view.single ? '1' : `${view.leased}/${view.nodes.length}`,
      unit: view.single ? 'node' : 'leased',
      sub: view.unowned
        ? `${view.unowned} shards unowned: writes 503`
        : down.length
          ? `${down.map((n) => n.node).join(', ')} down`
          : [view.single ? 'no leases' : shards, build].filter(Boolean).join(' · '),
      title: view.single ? undefined : `${shards}${build ? ` · ${build}` : ''}`,
    },
    {
      label: 'Requests',
      to: '/admin/metrics',
      tone: p5 === undefined ? 'idle' : tone(p5 > 0.5, p5 > 2),
      value: p5 === undefined ? '—' : `${p5.toFixed(2)}%`,
      unit: '5xx',
      sub: noM ? nometric : `of ${n1(http)} req/s · warn at 0.5%`,
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
      tone: limited === undefined ? 'idle' : tone(limited * 60 > 10 || heldSignInKeys(rlPoll.get().data).length > 0),
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
  const held = heldSignInKeys(rlPoll.get().data).length
  const parts = [a ? `${plural(a, 'account')} locked out` : '', held ? `${plural(held, 'sign-in')} held` : '']
  return parts.filter(Boolean).join(' · ') || 'nobody locked out'
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
  const cached = Object.values(m.gauges).reduce((a, g) => a + (g.cachedRepos ?? 0), 0)
  return (
    <Tiles
      tiles={[
        { label: 'Commits / s', right: `ops/s ${n1(last(c, 'ops'))}`, value: n1(last(c, 'commits')), spark: <Spark data={col(c, 'commits')} color="accent" />, to: P.nodes.path },
        { label: 'Commit → durable', right: 'p99 · p50 dashed', value: ms(last(c, 'durP99')), sec: `p50 ${ms(last(c, 'durP50'))}`, spark: <Spark data={col(c, 'durP99')} l2={col(c, 'durP50')} color="amber" th={0.5} /> },
        { label: 'Segment PUT', right: last(c, 'hedges') === undefined ? 'p99 · p50 dashed' : `hedges ${n1(last(c, 'hedges'))}/s`, value: ms(last(c, 'putP99')), sec: `p50 ${ms(last(c, 'putP50'))}`, spark: <Spark data={col(c, 'putP99')} l2={col(c, 'putP50')} color="amber" />, to: P.storage.path },
        { label: 'HTTP requests / s', right: '5xx in the health line', value: n1(http), spark: <Spark data={col(c, 'http')} color="c2" />, to: '/admin/metrics' },
        { label: 'Firehose emit delay', right: 'p99', value: ms(last(c, 'emitP99')), spark: <Spark data={col(c, 'emitP99')} color="violet" th={2} />, to: P.firehose.path },
        { label: 'Cold repo loads / s', right: `${fmtNum(cached)} in memory`, value: n1(last(c, 'loads')), spark: <Spark data={col(c, 'loads')} color="c6" /> },
      ]}
    />
  )
}

/** Lists only: what names a subscriber, a case, a held account, a relay or an operator. The figures are in the health line. */
function Rail({ subs }: { subs?: SubscriberList }) {
  const cases = openCasesPoll.use()
  const audit = auditPoll.use()
  const locks = lockoutsPoll.use()
  const rl = rlPoll.use()
  const cr = crawlersPoll.use()
  const factorLocks = locks.data?.supported ? locks.data.data : []
  const heldKeys = heldSignInKeys(rl.data)
  return (
    <aside className="cx-rail cx-stack">
      <Panel title="Subscribers" to={P.firehose.path} src={<Src>listFirehoseSubscribers</Src>} right={subs ? <span className="muted sm">{fmtNum(subs.live)} live</span> : undefined}>
        {subs?.subscribers.slice(0, 5).map((s) => (
          <RRow key={`${s.node}/${s.conn}`} onClick={() => openPanel('sub', `${s.node}/${s.conn}`)} x={s.state === 'backfilling' ? 'backfilling' : isSlow(s) ? `${dur(s.lagMs ?? 0)} behind` : 'caught up'}>
            <Glyph k={s.state === 'backfilling' ? 'info' : isSlow(s) ? 'warn' : 'ok'} />
            <span className="mono sm">#{s.conn}</span>
            <span className="nm">{s.relay ? <span className="cx-chip acc">{s.relay}</span> : isThisBrowser(s) ? <span className="muted">this browser’s live tail</span> : s.userAgent.split(' ')[0] || s.ip}</span>
          </RRow>
        ))}
        {subs && subs.total > 5 && <RRow to={P.firehose.path} x={`${fmtNum(subs.total - 5)} more ›`}><span className="nm muted">All subscribers</span></RRow>}
        {subs && !subs.subscribers.length && <RRow x="">No subscribers right now</RRow>}
      </Panel>

      <Panel title="Moderation queue" to={P.moderation.path} src={<Src>listCases</Src>} right={cases.data?.length ? <span className="cx-chip warn">▲ {cases.data.length} open</span> : undefined}>
        {cases.error ? (
          <ErrorState error={cases.error} />
        ) : !cases.data ? (
          <Loading />
        ) : cases.data.length ? (
          cases.data.slice(0, 6).map((k) => (
            <RRow key={k.id} onClick={() => openPanel('case', k.id)} x={ago(Date.parse(k.createdAt))}>
              <Glyph k="warn" />
              <span className="nm">
                {k.subjects.map((s) => s.kind).join(' + ') || 'no subject yet'} · {k.source}
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

      <Panel title="Locked out" to={P.limits.path} src={<Src isNew={!locks.data?.supported}>listLockouts · getRateLimits</Src>}>
        {locks.data && !locks.data.supported ? <NeedsVersion what="Who is locked out" nsid={locks.data.nsid} /> : null}
        {factorLocks.slice(0, 5).map((l, i) => (
          <RRow key={`f${i}`} onClick={() => openPanel('account', l.did)} x={`${factorName(l.factor)} · clears in ${dur(l.lockedUntil - Date.now())}`}>
            <Glyph k="warn" />
            <span className="nm">{l.handle ? `@${l.handle}` : <span className="mono sm">{l.did}</span>}</span>
          </RRow>
        ))}
        {heldKeys.slice(0, 5).map((k) => (
          <RRow
            key={`k${k.bucket.name}/${k.c.key}`}
            onClick={() => (k.did ? openPanel('account', k.did) : openPanel('bucket', k.bucket.name))}
            x={`${shortName(k.bucket.name)} · clears in ${dur(k.c.resetMs - Date.now())}`}
            title={k.c.key}
          >
            <Glyph k="err" />
            <span className="nm">{k.ident ? (k.ident.includes('@') || k.ident.startsWith('did:') ? k.ident : `@${k.ident}`) : <span className="mono sm">{k.did}</span>}</span>
          </RRow>
        ))}
        {(locks.data?.supported ?? true) && rl.data && !factorLocks.length && !heldKeys.length && (
          <RRow>
            <Glyph k="ok" />
            <span className="nm">Nobody is locked out</span>
          </RRow>
        )}
      </Panel>

      <Panel title="Relays" to={P.firehose.path} src={<Src>getCrawlers</Src>}>
        {cr.error ? (
          <ErrorState error={cr.error} />
        ) : !cr.data ? (
          <Loading />
        ) : cr.data.relays.length ? (
          cr.data.relays.slice(0, 5).map((r) => (
            <RRow
              key={r.relay}
              onClick={() => openPanel('relay', r.relay)}
              x={!r.status ? 'not asked yet' : r.status.ok ? `accepted ${ago(r.status.lastAttemptMs)}` : `refused · ${r.status.httpStatus ?? 'no answer'}`}
            >
              <Glyph k={!r.status ? 'idle' : r.status.ok ? 'ok' : 'err'} />
              <span className="nm mono sm">{r.relay}</span>
            </RRow>
          ))
        ) : (
          <RRow>
            <Glyph k="idle" />
            <span className="nm">No relays: nothing is told about this PDS</span>
          </RRow>
        )}
      </Panel>

      <Panel title="Operator activity" to={`${P.moderation.path}#audit`} src={<Src>getAuditLog</Src>}>
        {audit.error ? (
          <ErrorState error={audit.error} />
        ) : !audit.data ? (
          <Loading />
        ) : audit.data.length ? (
          audit.data.slice(0, 5).map((e) => (
            <RRow key={e.id} onClick={() => openPanel('audit', e.id)} x={ago(Date.parse(e.at))}>
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
  const started = useStartedAt()
  const subs = subscribersPoll.use()
  const locks = lockoutsPoll.use()
  const feed = segmentsPoll.use().data?.supported
  openCasesPoll.use()
  if (!view) return error ? <ErrorState error={error} retry={clusterPoll.refresh} /> : <Loading label="Asking the cluster…" />
  return (
    <>
      <Banners items={clusterBanners(view, subs.data, locks.data)} />
      <HealthLine cells={health(view, m, started, subs.data)} />
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
        <Rail subs={subs.data} />
      </div>
    </>
  )
}
