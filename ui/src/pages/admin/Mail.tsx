import { useState } from 'react'
import { DataTable } from '../../components/console/DataTable'
import { Banners, Chip, ErrorState, Glyph, Loading, Meter, NeedsVersion, PageHead, Panel, Seg, Spark, Src, Swatch, Tiles, type BannerSpec } from '../../components/console/kit'
import { registerPalette } from '../../components/console/Palette'
import { useClusterView } from '../../lib/console/cluster'
import { ago, dur, fmtNum, plural } from '../../lib/console/fmt'
import { configPoll, mailBudgetPoll, mailPoll, missing, sumSeries, useNodeMetrics, type MailBudget } from '../../lib/console/sys'
import type { MailEntry, MailStatus } from '../../lib/adminApi'
import { navigate } from '../../lib/router'

// Mail: each node's queue, the budgets that hold sends back, and the recent mail log. The log
// keeps the purpose, the recipient's domain and the outcome; never an address, body or code.

export const mailId = (m: MailEntry) => `${m.node}:${m.id}`

export function MailChip({ m }: { m: Pick<MailEntry, 'status' | 'attempts'> }) {
  switch (m.status) {
    case 'sent':
      return <Chip k="ok">sent</Chip>
    case 'logged':
      return <Chip k="info">logged (dev)</Chip>
    case 'queued':
      return <Chip k="info">queued</Chip>
    case 'retrying':
      return <Chip k="warn">retrying {m.attempts}/3</Chip>
    case 'failed':
      return <Chip k="err">failed</Chip>
    case 'dropped':
      return <Chip k="err">dropped</Chip>
    case 'suppressed':
      return <Chip k="idle">suppressed</Chip>
  }
  return <Chip k="plain">{m.status}</Chip>
}

export const BUDGET_TEXT: Record<string, string> = {
  'mail-cluster-day': 'the whole cluster, per UTC day',
  'mail-node-hour': 'each node, per hour',
  'mail-recipient-hour': 'each recipient, per hour',
  'mail-recipient-day': 'each recipient, per day',
}
const per = (secs: number) => (secs === 86400 ? 'day' : secs === 3600 ? 'hour' : dur(secs * 1000))

/** How mail leaves this cluster, from the flags. */
export function transportOf(flag: (f: string) => { value?: string; source: string } | undefined) {
  const set = (f: string) => {
    const s = flag(f)
    return !!s && s.source !== 'unset' && s.source !== 'default'
  }
  if (set('--email-api-url')) return `mail API · ${flag('--email-api-url')?.value?.replace(/^https?:\/\//, '').split('/')[0] ?? ''}`
  if (set('--email-smtp-url') || set('--email-smtp-url-file')) return 'SMTP'
  if (flag('--dev-mode')?.value === 'true') return 'dev mode: logged, not sent'
  return 'no transport set: nothing is sent'
}

registerPalette({
  items: () => [
    { group: 'Go to', title: 'Mail: failed and retrying', desc: 'the mail log', glyph: '✉', run: () => navigate('/admin/mail?status=problems') },
    { group: 'Go to', title: 'Mail budgets', desc: 'mail-cluster-day, mail-node-hour', glyph: '✉', run: () => navigate('/admin/mail') },
  ],
})

type Filter = 'all' | 'problems' | 'sent' | 'suppressed'
const PROBLEM: MailStatus[] = ['failed', 'dropped', 'retrying']

export function Mail() {
  const mail = mailPoll.use()
  const bud = mailBudgetPoll.use()
  const cfg = configPoll.use()
  const m = useNodeMetrics()
  const { view } = useClusterView()
  const [filter, setFilter] = useState<Filter>(() => (new URLSearchParams(location.search).get('status') === 'problems' ? 'problems' : 'all'))
  const color = (n: string) => view?.nodes.find((x) => x.node === n)?.color

  if (!mail.data) {
    if (mail.error && missing(mail.error))
      return (
        <>
          <PageHead title="Mail" />
          <Panel>
            <NeedsVersion what="The mail log" nsid="vlpds.admin.listMail" />
          </Panel>
        </>
      )
    return mail.error ? <ErrorState error={mail.error} retry={mailPoll.refresh} /> : <Loading />
  }
  const d = mail.data
  const self = cfg.data?.find((r) => r.self && r.config)?.config
  const flag = (f: string) => self?.settings.find((s) => s.flag === f)
  const from = flag('--email-from-address')?.value
  const queued = d.nodes.reduce((t, n) => t + (n.queued ?? 0), 0)
  const count = (s: MailStatus[]) => d.mail.filter((x) => s.includes(x.status)).length
  const oldest = d.mail.length ? Math.min(...d.mail.map((x) => x.at)) : undefined
  const budgets = bud.data?.budgets ?? []
  const day = budgets.find((b) => b.limiter === 'mail-cluster-day')
  const dayUsed = day?.top[0]?.used ?? 0
  const nodeHour = budgets.find((b) => b.limiter === 'mail-node-hour')

  const purposes = new Map<string, { purpose: string; total: number; sent: number; bad: number; suppressed: number; last: number }>()
  for (const x of d.mail) {
    const p = purposes.get(x.purpose) ?? { purpose: x.purpose, total: 0, sent: 0, bad: 0, suppressed: 0, last: 0 }
    p.total++
    if (x.status === 'sent' || x.status === 'logged') p.sent++
    if (PROBLEM.includes(x.status)) p.bad++
    if (x.status === 'suppressed') p.suppressed++
    p.last = Math.max(p.last, x.at)
    purposes.set(x.purpose, p)
  }

  const rows = d.mail.filter((x) =>
    filter === 'all' ? true : filter === 'problems' ? PROBLEM.includes(x.status) : filter === 'sent' ? x.status === 'sent' || x.status === 'logged' : x.status === 'suppressed',
  )

  const banners: BannerSpec[] = []
  if (d.unreachableNodes?.length) banners.push({ id: 'unreach', tone: 'warn', title: `${d.unreachableNodes.join(', ')} didn't answer`, desc: 'Their queues and mail are missing below.' })
  const failed = count(['failed', 'dropped'])
  if (failed) banners.push({ id: 'failed', tone: 'err', title: `${plural(failed, 'mail')} failed or dropped`, desc: 'in the log below. Dropped means the node’s queue was full.' })
  if (day?.enabled && dayUsed >= day.points * 0.9)
    banners.push({ id: 'budget', tone: dayUsed >= day.points ? 'err' : 'warn', title: `Cluster mail budget ${dayUsed >= day.points ? 'spent' : 'nearly spent'}`, desc: `${fmtNum(dayUsed)} of ${fmtNum(day.points)} today. Account mail past it is suppressed until the UTC day ends.` })
  if (bud.data && !bud.data.enabled) banners.push({ id: 'rloff', tone: 'info', title: 'Rate limits are off', desc: 'so no mail budget applies.' })

  return (
    <>
      <PageHead
        title="Mail"
        sub={
          <>
            {self && <span>{transportOf(flag)}</span>}
            {from && (
              <span>
                from <span className="mono">{from}</span>
              </span>
            )}
            <span>4 sends at a time per node · 3 tries</span>
          </>
        }
      />
      <Banners items={banners} />
      <Tiles
        boxed
        tiles={[
          { label: 'Queued', right: 'all nodes · 1,024 per node', value: fmtNum(queued), spark: <Spark data={sumSeries(m.nodes, 'mailQueue')} color="info" /> },
          { label: 'Sent', right: oldest ? `in the log · since ${ago(oldest).replace(' ago', '')}` : 'in the log', value: fmtNum(count(['sent', 'logged'])) },
          { label: 'Retrying', value: fmtNum(count(['retrying', 'queued'])) },
          { label: 'Failed · dropped', value: fmtNum(failed) },
          { label: 'Suppressed by budgets', value: fmtNum(count(['suppressed'])) },
          {
            label: 'Cluster budget today',
            right: 'UTC day',
            value: day ? fmtNum(dayUsed) : '—',
            unit: day ? `/ ${fmtNum(day.points)}` : undefined,
            spark: day ? (
              <div style={{ marginTop: 9 }}>
                <Meter v={dayUsed} max={day.points} wide k={dayUsed >= day.points * 0.9 ? 'warn' : undefined} />
              </div>
            ) : undefined,
          },
        ]}
      />
      <div className="cx-grid2 cx-mt" style={{ gridTemplateColumns: 'minmax(0,.85fr) minmax(0,1.15fr)' }}>
        <div className="cx-stack">
          <Panel title="Queues" src={<Src>listMail · nodes</Src>}>
            <DataTable
              compact
              rows={d.nodes}
              rowKey={(n) => n.node}
              cols={[
                {
                  id: 'n',
                  label: 'Node',
                  render: (n) => (
                    <span className="cx-cellid">
                      <Swatch color={color(n.node)} />
                      <span className="mono">{n.node}</span>
                      {n.self && <Chip k="acc">this node</Chip>}
                    </span>
                  ),
                },
                {
                  id: 'q',
                  label: 'Queued',
                  r: true,
                  render: (n) =>
                    !n.reachable ? (
                      <Chip k="err">no answer</Chip>
                    ) : (
                      <span className="cx-cellid end">
                        <Meter v={n.queued ?? 0} max={1024} k={(n.queued ?? 0) > 512 ? 'warn' : undefined} />
                        <span className="mono">{fmtNum(n.queued ?? 0)}</span>
                      </span>
                    ),
                },
                {
                  id: 'h',
                  label: 'Sent this hour',
                  r: true,
                  title: 'mail-node-hour: account mail this node sent in the current window',
                  render: (n) => {
                    const t = nodeHour?.top[0]
                    if (!nodeHour) return <span className="muted">—</span>
                    // the bucket reports its total and its busiest node; one node alone is exact
                    const used = !t || !t.nodes.includes(n.node) ? 0 : t.nodes.length === 1 ? t.used : undefined
                    return (
                      <span className="mono" title={used === undefined ? `the busiest node sent ${t!.maxNodeUsed}` : undefined}>
                        {used === undefined ? `≤ ${fmtNum(t!.maxNodeUsed)}` : fmtNum(used)} <span className="muted">/ {fmtNum(nodeHour.points)}</span>
                      </span>
                    )
                  },
                },
              ]}
            />
          </Panel>
          <Panel title="Budgets" src={<Src>getRateLimits · mail-*</Src>} foot="Budgets are rate-limit buckets: change them on Limits & lockouts. A suppressed mail is never retried.">
            {bud.error ? (
              <ErrorState error={bud.error} retry={mailBudgetPoll.refresh} />
            ) : !bud.data ? (
              <Loading />
            ) : (
              <DataTable
                compact
                rows={budgets}
                rowKey={(b: MailBudget) => b.limiter}
                empty={<div className="cx-empty">This server has no mail buckets.</div>}
                cols={[
                  {
                    id: 'l',
                    label: 'Bucket',
                    render: (b) => (
                      <span>
                        <span className="mono sm">{b.limiter}</span> <span className="muted sm">{BUDGET_TEXT[b.limiter] ?? ''}</span>
                      </span>
                    ),
                  },
                  { id: 'p', label: 'Limit', r: true, render: (b) => (b.enabled ? <span className="mono">{fmtNum(b.points)}/{per(b.windowSecs)}</span> : <Chip k="idle">off</Chip>) },
                  {
                    id: 'u',
                    label: 'Used',
                    title: 'The cluster’s total; for the other buckets, the busiest node or recipient',
                    r: true,
                    render: (b) => {
                      const busiest = b.limiter === 'mail-node-hour' ? (b.top[0]?.maxNodeUsed ?? 0) : Math.max(0, ...b.top.map((x) => x.used))
                      return (
                        <span className="cx-cellid end" title={b.limiter === 'mail-cluster-day' ? undefined : 'the busiest node or recipient'}>
                          <Meter v={busiest} max={b.points} k={busiest >= b.points * 0.9 ? 'warn' : undefined} />
                          <span className="mono">{fmtNum(busiest)}</span>
                        </span>
                      )
                    },
                  },
                ]}
              />
            )}
          </Panel>
          <Panel title="By purpose" src={<Src>listMail</Src>} right={<span className="muted sm">in the log</span>}>
            <DataTable
              compact
              rows={[...purposes.values()].sort((a, b) => b.total - a.total)}
              rowKey={(p) => p.purpose}
              empty={<div className="cx-empty">No mail since the nodes started.</div>}
              cols={[
                { id: 'p', label: 'Purpose', render: (p) => <span className="mono sm">{p.purpose}</span> },
                { id: 's', label: 'Sent', r: true, render: (p) => <span className="mono">{fmtNum(p.sent)}</span> },
                { id: 'b', label: 'Failed', r: true, render: (p) => (p.bad ? <span className="s-err"><Glyph k="err" /> {fmtNum(p.bad)}</span> : <span className="muted">0</span>) },
                { id: 'x', label: 'Suppressed', r: true, render: (p) => <span className="mono">{fmtNum(p.suppressed)}</span> },
                { id: 'l', label: 'Last', r: true, render: (p) => ago(p.last) },
              ]}
            />
          </Panel>
        </div>
        <Panel
          title="Recent messages"
          src={<Src>vlpds.admin.listMail · 5 s</Src>}
          right={
            <Seg
              label="Show"
              value={filter}
              onChange={setFilter}
              options={[
                { v: 'all', label: 'All', n: d.mail.length },
                { v: 'problems', label: 'Problems', n: count(PROBLEM) },
                { v: 'sent', label: 'Sent', n: count(['sent', 'logged']) },
                { v: 'suppressed', label: 'Suppressed', n: count(['suppressed']) },
              ]}
            />
          }
          foot="Only the purpose, the recipient's domain and the outcome are kept, the last 200 per node, in memory. Bodies, codes and addresses never are."
        >
          <DataTable
            compact
            rows={rows}
            rowKey={mailId}
            open={(x) => ({ type: 'mail', id: mailId(x) })}
            empty={<div className="cx-empty">{d.mail.length ? 'Nothing matches.' : 'No mail since the nodes started.'}</div>}
            cols={[
              { id: 'at', label: 'When', sort: (a, b) => a.at - b.at, render: (x) => ago(x.at) },
              { id: 'p', label: 'Purpose', render: (x) => <span className="mono sm">{x.purpose}</span> },
              { id: 't', label: 'To', render: (x) => <span className="t2">…@{x.toDomain}</span> },
              {
                id: 'n',
                label: 'Node',
                render: (x) => (
                  <span className="cx-cellid">
                    <Swatch color={color(x.node)} />
                    <span className="mono sm t2">{x.node.replace(/^vlpds-/, '')}</span>
                  </span>
                ),
              },
              { id: 'r', label: 'Result', render: (x) => <MailChip m={x} /> },
            ]}
          />
        </Panel>
      </div>
    </>
  )
}

