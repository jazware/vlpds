import { useEffect, useState } from 'react'
import { DataTable, type Col } from '../../components/console/DataTable'
import { Chip, Empty, ErrorState, Loading, oldest, PageHead, Panel, Seg, Src, Tiles } from '../../components/console/kit'
import { panelParam } from '../../components/console/nav'
import { ago, auditSubjectText, authShort, fmtBytes } from '../../lib/console/fmt'
import {
  CASE_STATUSES,
  CASE_TONE,
  fmtGB,
  shortUri,
  subjectQuery,
  useAudit,
  useCases,
  useOverQuota,
  useTakedowns,
  type AuditEntry,
  type Case,
  type SubjectRef,
  type TakedownEntry,
} from '../../lib/console/moderation'
import { navigate, useHash, useSearch } from '../../lib/router'
import { AuditAction } from './auditUi'
import { confirmModerate, newCaseDialog, reviewSubject, SubjectLabel } from './moderationUi'
import { AccountLink, Who } from './peopleUi'

// Moderation: look up a subject, the cases queue, active takedowns and the audit log. Cases,
// subjects and audit entries open in the slide-over (moderationUi.tsx).

export type { AuditEntry }

/** The Spaces page's take down / restore button (it predates the console kit). */
export function ModerateButton({ subject, applied, onDone, caseId }: { subject: SubjectRef; applied: boolean; onDone: () => void; caseId?: string }) {
  return (
    <button type="button" className={`btn sm ${applied ? '' : 'danger'}`} onClick={async () => (await confirmModerate({ subject, restore: applied, caseId })) && onDone()}>
      {applied ? 'Restore…' : 'Take down…'}
    </button>
  )
}

const ISO = (s: string) => Date.parse(s)
type Status = Case['status'] | 'all'

export function Moderation() {
  const search = useSearch()
  // older links: ?q= looked a subject up, ?tab= picked a tab
  useEffect(() => {
    const q = search.get('q')
    const tab = search.get('tab')
    if (!q && !tab) return
    const sp = new URLSearchParams(location.search)
    sp.delete('q')
    sp.delete('tab')
    if (q) sp.set('open', panelParam('subject', q))
    navigate(`/admin/moderation${sp.size ? `?${sp}` : ''}${tab === 'audit' ? '#audit' : location.hash}`, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  // #audit: Overview's "Operator activity ›" and ⌘K's "Audit log" land on the panel
  const hash = useHash()
  useEffect(() => {
    if (hash !== '#audit') return
    let tries = 0
    const t = setInterval(() => {
      const el = document.getElementById('audit')
      if (el?.querySelector('table, .cx-empty') || ++tries > 20) {
        clearInterval(t)
        el?.scrollIntoView({ block: 'start' })
      }
    }, 100)
    return () => clearInterval(t)
  }, [hash])
  const cases = useCases()
  const takedowns = useTakedowns()
  const quota = useOverQuota()
  const [status, setStatus] = useState<Status>('open')
  const [lookup, setLookup] = useState('')

  const all = cases.data ?? []
  const open = all.filter((c) => c.status === 'open').sort((a, b) => ISO(a.createdAt) - ISO(b.createdAt))
  const weekAgo = Date.now() - 7 * 86400_000
  const actioned7 = all.filter((c) => c.status === 'actioned' && ISO(c.updatedAt) > weekAgo)
  const tds = takedowns.data ?? []
  const byKind = (['account', 'record', 'blob', 'space'] as const).map((k) => [k, tds.filter((t) => t.subject.kind === k).length] as const).filter(([, n]) => n)
  const over = quota.data ?? []

  return (
    <>
      <PageHead
        title="Moderation"
        sub={
          <>
            <span>takedowns, cases and the audit log are kept in the bucket</span>
            <span>only content stored on this PDS can be acted on</span>
          </>
        }
        updated={oldest(cases.at, takedowns.at)}
        actions={
          <button type="button" className="cx-btn" onClick={() => newCaseDialog()}>
            New case…
          </button>
        }
      />
      <section className="cx-pn cx-mb">
        <form
          className="cx-toolbar"
          style={{ borderBottom: 0 }}
          onSubmit={(e) => {
            e.preventDefault()
            const q = lookup.trim().replace(/^@/, '')
            if (q) reviewSubject(q)
          }}
        >
          <input
            className="cx-inp mono"
            data-search
            value={lookup}
            onChange={(e) => setLookup(e.target.value)}
            placeholder="Look up a bsky.app URL, at:// URI, handle, DID or DID + blob CID"
            aria-label="Look up a subject"
            spellCheck={false}
            autoComplete="off"
          />
          <button className="cx-btn">Look up</button>
          <Src>resolveSubject · getSubject</Src>
        </form>
      </section>
      <Tiles
        boxed
        tiles={[
          { label: 'Open cases', right: open.length ? `oldest ${ago(ISO(open[0].createdAt)).replace(' ago', '')}` : undefined, value: cases.data ? open.length : '—' },
          { label: 'Actioned, 7 days', value: cases.data ? actioned7.length : '—', sec: cases.data ? `${all.length} cases in all` : undefined },
          { label: 'Active takedowns', right: byKind.map(([k, n]) => `${n} ${k}`).join(' · ') || undefined, value: takedowns.data ? tds.length : '—' },
          { label: 'Over blob quota', right: 'migrations only', value: quota.data ? over.length : '—' },
        ]}
      />
      <div className="cx-grid2 cx-mt">
        <Panel
          title="Cases"
          src={<Src>listCases · getCase · updateCase</Src>}
          right={
            <Seg<Status>
              label="Status"
              value={status}
              onChange={setStatus}
              options={[...CASE_STATUSES, 'all' as const].map((s) => ({ v: s, label: s, n: s === 'all' ? all.length : all.filter((c) => c.status === s).length }))}
            />
          }
        >
          {cases.error && !cases.data ? <ErrorState error={cases.error} retry={cases.reload} /> : !cases.data ? <Loading /> : <CasesTable rows={all.filter((c) => status === 'all' || c.status === status)} status={status} />}
        </Panel>
        <div className="cx-stack">
          <Panel title="Active takedowns" src={<Src>listTakedowns</Src>}>
            {takedowns.error && !takedowns.data ? <ErrorState error={takedowns.error} retry={takedowns.reload} /> : !takedowns.data ? <Loading /> : <TakedownsTable rows={tds} />}
          </Panel>
          <AuditPanel />
          {over.length > 0 && (
            <Panel title="Over blob quota" src={<Src>listOverQuota</Src>} foot="Only a migration can put an account here: blobs of a repo moving in are never refused.">
              <DataTable
                compact
                rows={over}
                rowKey={(a) => a.did}
                open={(a) => ({ type: 'subject', id: a.did })}
                cols={[
                  { id: 'who', label: 'Account', render: (a) => <AccountLink did={a.did} /> },
                  { id: 'use', label: 'Stored', r: true, render: (a) => <span className="mono">{fmtGB(a.bytes)} / {fmtGB(a.limit)}</span> },
                  { id: 'at', label: 'Since', r: true, render: (a) => ago(ISO(a.at)) },
                ]}
              />
            </Panel>
          )}
        </div>
      </div>
    </>
  )
}

function CasesTable({ rows, status }: { rows: Case[]; status: Status }) {
  const cols: Col<Case>[] = [
    {
      id: 'subj',
      label: 'Subject',
      render: (c) =>
        c.subjects.length ? (
          <span className="cx-cellid">
            <Who did={c.subjects[0].did} />
            <span className="muted sm">{c.subjects.map((s) => s.kind).join(' + ')}</span>
          </span>
        ) : (
          <span className="muted">none yet</span>
        ),
    },
    { id: 'src', label: 'Source', className: 'trunc', style: { maxWidth: 220 }, render: (c) => <span className="t2" title={`${c.source}\ncase ${c.id}`}>{c.source}</span> },
    { id: 'opened', label: 'Opened', r: true, sort: (a, b) => ISO(a.createdAt) - ISO(b.createdAt), render: (c) => ago(ISO(c.createdAt)) },
    { id: 'status', label: 'Status', render: (c) => <Chip k={CASE_TONE[c.status]}>{c.status}</Chip> },
  ]
  return (
    <DataTable
      rows={rows}
      cols={cols}
      rowKey={(c) => c.id}
      open={(c) => ({ type: 'case', id: c.id })}
      sort={{ id: 'opened' }}
      empty={<Empty title={status === 'all' ? 'No cases' : `No ${status} cases`}>Open one per notice or report (DMCA, abuse report, law enforcement) to track it here.</Empty>}
      label="Cases"
    />
  )
}

function TakedownsTable({ rows }: { rows: TakedownEntry[] }) {
  return (
    <DataTable
      compact
      rows={rows}
      rowKey={(t) => `${t.subject.kind}:${subjectQuery(t.subject)}`}
      open={(t) => ({ type: 'subject', id: subjectQuery(t.subject) })}
      label="Active takedowns"
      empty={<Empty title="No active takedowns">Takedowns made here or by a moderation service show up here.</Empty>}
      cols={[
        { id: 'kind', label: 'Kind', render: (t) => <Chip k={t.subject.kind === 'account' ? 'err' : 'warn'}>{t.subject.kind}</Chip> },
        { id: 'subj', label: 'Subject', className: 'trunc', style: { maxWidth: 190 }, render: (t) => <SubjectLabel s={t.subject} /> },
        { id: 'why', label: 'Reason', className: 'trunc', style: { maxWidth: 130 }, render: (t) => <span className="t2" title={t.reason ?? t.ref}>{t.reason ?? (t.ref ? `ref ${t.ref}` : '—')}</span> },
        { id: 'at', label: 'When', r: true, render: (t) => ago(ISO(t.at)) },
        {
          id: 'bytes',
          label: 'Bytes',
          r: true,
          render: (t) =>
            t.subject.kind !== 'blob' ? <span className="muted">—</span> : t.purgedAtMs ? 'purged' : t.quarantined ? <span title={`quarantined until ${new Date(t.purgeAfterMs ?? 0).toLocaleString()}`}>{t.size ? fmtBytes(t.size) : 'held'}</span> : 'none',
        },
      ]}
    />
  )
}

function AuditPanel() {
  const scope0 = new URLSearchParams(location.search).get('scope') === 'spaces' ? 'spaces' : 'all'
  const [scope, setScope] = useState<'all' | 'spaces'>(scope0)
  const [limit, setLimit] = useState(25)
  const l = useAudit({ limit, space: scope === 'spaces' ? '*' : undefined })
  const rows = l.data ?? []
  return (
    <Panel
      id="audit"
      className="cx-anchor"
      title="Audit log"
      src={<Src>getAuditLog</Src>}
      right={<Seg label="Entries" value={scope} onChange={setScope} options={[{ v: 'all', label: 'all' }, { v: 'spaces', label: 'spaces' }]} />}
      foot={
        <>
          <span>Every operator change (takedowns, account and key changes, invites, mail, shards, domains, limits and relays) and every read of space data: who, how they signed in, from where, why.</span>
          {rows.length >= limit && limit < 200 && (
            <button type="button" className="cx-linklike" style={{ marginLeft: 'auto' }} onClick={() => setLimit((n) => Math.min(200, n * 2))}>
              Show more
            </button>
          )}
        </>
      }
    >
      {l.error && !l.data ? (
        <ErrorState error={l.error} retry={l.reload} />
      ) : !l.data ? (
        <Loading />
      ) : (
        <DataTable
          compact
          rows={rows}
          rowKey={(e) => e.id}
          open={(e) => ({ type: 'audit', id: e.id })}
          label="Audit log"
          empty={<Empty title="Nothing yet" />}
          cols={[
            { id: 'at', label: 'When', render: (e) => ago(ISO(e.at)) },
            {
              id: 'who',
              label: 'Who',
              render: (e) => (
                <>
                  {e.actor} <span className="muted mono sm">{[authShort(e.auth), e.node].filter(Boolean).join(' · ')}</span>
                </>
              ),
            },
            {
              id: 'act',
              label: 'Action',
              render: (e) => <AuditAction a={e.action} />,
            },
            {
              id: 'subj',
              label: 'Subject',
              className: 'trunc',
              style: { maxWidth: 220 },
              render: (e) => (e.subject ? e.subject.kind === 'account' ? <Who did={e.subject.did} /> : <span className="mono sm t2">{shortUri(auditSubjectText(e.subject))}</span> : <span className="muted">{e.reason ?? '—'}</span>),
            },
          ]}
        />
      )}
    </Panel>
  )
}
