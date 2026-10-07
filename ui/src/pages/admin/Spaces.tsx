import { useEffect, useState, type ReactNode } from 'react'
import { DataTable, type Col } from '../../components/console/DataTable'
import { confirmAction } from '../../components/console/dialogs'
import { DetailPage, registerDetail } from '../../components/console/Drawer'
import { Banners, Chip, Copy, Empty, ErrorState, Json, KV, Loading, Meter, PageHead, Panel, Sec, Seg, Src, Strip, Swatch, Tiles, type BannerSpec } from '../../components/console/kit'
import { registerPalette } from '../../components/console/Palette'
import { useClusterView } from '../../lib/console/cluster'
import { ago, authName, fmtNum, plural, shortDid } from '../../lib/console/fmt'
import { K } from '../../lib/console/keys'
import { moderate as moderateSubject, useAudit } from '../../lib/console/moderation'
import { mutate } from '../../lib/console/mutate'
import { useAdminQuery } from '../../lib/console/query'
import { subjectTone } from '../../lib/console/status'
import { spacesStatusQ, type SpacesStatus } from '../../lib/console/sys'
import { Link, navigate, useSearch } from '../../lib/router'
import { admin, call } from '../../lib/xrpc'

type HealthRow = { node: string; status?: SpacesStatus; error?: unknown }

// Spaces (alpha): spaces whose authority lives here, every node's Spaces health, and one
// space's members, writers, registrations and takedowns. Metadata only: a record's value is
// shown only after an audited read with a reason (listSpaceRecords).

type Rev = { rev: string; at?: string } | null
export type SpaceRow = {
  uri: string
  authority: string
  handle?: string
  spaceType: string
  skey: string
  readPolicy: string
  writePolicy: string
  appAccess: string
  createdAt: string
  deletedAt?: string
  takendown: boolean
  members: number
  writers: number
  repos: number
  records: number
  lastSpaceRev?: string
  lastActivityUs: number
}
type Totals = { spaces: number; deletedSpaces: number; takendown: number; members: number; writers: number; spaceRepos: number; records: number; foreignSpaces: number }
type ListOut = { totals: Totals; count: number; spaces: SpaceRow[]; cursor?: string; truncated?: boolean; countCap: number; unreachableNodes?: string[] }
type Writer = { did: string; handle?: string | null; repoRev: Rev; spaceRev: Rev; hash: string; local: boolean; records?: number; headRev?: Rev; takendownRecords?: number }
type Registration = { service: string; host?: string | null; expiresAt?: string; expired: boolean }
type SpaceInfo = {
  space: { uri: string; authority: string; handle?: string | null; spaceType: string; skey: string; readPolicy: string; writePolicy: string; appAccess: string; createdAt: string; deletedAt?: string | null; takendown: boolean }
  members: { did: string; handle?: string | null; read: boolean; write: boolean }[]
  moreMembers: boolean
  writers: Writer[]
  moreWriters: boolean
  activity: { spaceRev: string; at?: string; writer: string }[]
  registrations: Registration[]
  takendownRecords: { uri: string; did: string }[]
}
type Audit = { id: string; at: string; actor: string; auth?: string; ip?: string; action: string; subject?: { kind: string; did: string; uri?: string }; reason?: string; detail?: { method?: string; service?: string } }
type SpaceRecord = { uri: string; cid: string; value: unknown; takendown: boolean }

/** The slide-over for a space (old /admin/spaces/space?uri= links still land on its full page). */
export const spaceUrl = (uri: string) => `/admin/spaces?open=${encodeURIComponent(`space:${uri}`)}`
const accountUrl = (did: string) => `/admin/accounts/${encodeURIComponent(did)}`
const lookupUrl = (q: string) => `/admin/moderation?q=${encodeURIComponent(q)}`

/** at://{authority}/space/{type}/{skey}[/{author}/{collection}/{rkey}] */
export function parseSpaceUri(s: string) {
  const m = /^at:\/\/([^/]+)\/space\/([^/]+)\/([^/]+)(?:\/([^/]+)\/([^/]+)\/([^/]+))?\/?$/.exec(s.trim())
  if (!m) return null
  return { space: `at://${m[1]}/space/${m[2]}/${m[3]}`, authority: m[1], record: m[4] ? { author: m[4], collection: m[5], rkey: m[6] } : undefined }
}
const spaceLabel = (uri: string) => {
  const p = uri.replace(/^at:\/\//, '').split('/')
  return `${p[2]} / ${p[3]}`
}

/** Whether this server runs Spaces (describeServer's `vlpds.spaces`). */
export function useSpacesOn() {
  const d = useAdminQuery<{ vlpds?: { spaces?: boolean } }>({ key: K.describe, fn: (signal) => call('com.atproto.server.describeServer', { signal }), staleTime: Infinity })
  return { ...d, data: d.data ? !!d.data.vlpds?.spaces : undefined }
}

const when = (at?: string | number | null) => (at ? ago(typeof at === 'number' ? at : Date.parse(at)) : <span className="muted">—</span>)

function Who({ did, handle }: { did: string; handle?: string | null }) {
  return handle ? (
    <Link to={accountUrl(did)} title={did} onClick={(e) => e.stopPropagation()}>
      @{handle}
    </Link>
  ) : (
    <Copy text={did}>{shortDid(did)}</Copy>
  )
}

function StateChip({ s }: { s: { takendown: boolean; deletedAt?: string | null } }) {
  if (!s.takendown && s.deletedAt) return <Chip k="idle">deleted</Chip>
  const [k, t] = subjectTone(s.takendown)!
  return <Chip k={k}>{t}</Chip>
}

/** Take down or restore a space, a record or a space repo (vlpds.admin.moderate), with a reason. */
export function moderate(subject: { kind: 'space' | 'record'; did: string; uri: string }, restore: boolean, done: () => void) {
  const what = subject.kind === 'space' ? 'space' : 'space record'
  return confirmAction({
    tone: restore ? 'warn' : 'err',
    primary: restore,
    title: restore ? `Restore this ${what}?` : `Take down this ${what}?`,
    items: restore
      ? ['Lifts the takedown: members get credentials and notifies again.', <span className="mono sm" style={{ overflowWrap: 'anywhere' }}>{subject.uri}</span>]
      : subject.kind === 'space'
        ? ['No one gets a credential to read it, and syncers can’t list its writers or register for its notifications.', 'Members’ notifies are dropped. Reversible: Restore lifts it.', <span className="mono sm" style={{ overflowWrap: 'anywhere' }}>{subject.uri}</span>]
        : ['The record stops being served to the space’s members; its author still holds it.', <span className="mono sm" style={{ overflowWrap: 'anywhere' }}>{subject.uri}</span>],
    fields: [
      { id: 'reason', label: 'Reason (kept in the audit log)', required: true, type: 'textarea' },
      { id: 'caseId', label: 'Case id (optional)' },
    ],
    action: restore ? 'Restore' : 'Take down',
    call: `vlpds.admin.moderate {"kind": "${subject.kind}", "action": "${restore ? 'restore' : 'takedown'}"}`,
    run: (v) => moderateSubject(subject, restore, String(v.reason), String(v.caseId ?? '').trim() || undefined).then(done),
    done: restore ? 'Restored' : 'Taken down',
  })
}

// ---------------------------------------------------------------- the section

const SORTS = [
  { v: 'activity', label: 'Recent' },
  { v: 'members', label: 'Members' },
  { v: 'writers', label: 'Writers' },
  { v: 'records', label: 'Records' },
  { v: 'created', label: 'Newest' },
] as const
type Sort = (typeof SORTS)[number]['v']
const PAGE = 50

let lastList: SpaceRow[] = []
registerPalette({
  items: (q) => {
    const out = lastList.map((s) => ({
      group: 'Go to',
      title: `Space ${s.skey}`,
      desc: `${s.spaceType}${s.handle ? ` · @${s.handle}` : ''}`,
      hay: s.uri,
      glyph: '◌',
      run: () => navigate(spaceUrl(s.uri)),
    }))
    const p = parseSpaceUri(q)
    if (p)
      out.unshift({
        group: 'Look up',
        title: p.record ? 'Look up this space record' : `Open space ${spaceLabel(p.space)}`,
        desc: p.record ? 'in Moderation' : 'getSpaceInfo',
        hay: q,
        glyph: '⌕',
        run: () => navigate(p.record ? lookupUrl(q.trim()) : spaceUrl(p.space)),
      })
    return out
  },
})

function OpenSpace() {
  const [v, setV] = useState('')
  const [bad, setBad] = useState(false)
  return (
    <form
      className="cx-form-row"
      onSubmit={(e) => {
        e.preventDefault()
        const p = parseSpaceUri(v)
        if (!p) return setBad(true)
        navigate(p.record ? lookupUrl(v.trim()) : spaceUrl(p.space))
      }}
    >
      <input
        className="cx-inp mono"
        style={{ width: 300, maxWidth: '100%', ...(bad ? { borderColor: 'var(--err)' } : {}) }}
        placeholder="at://… space or record URI"
        aria-label="Open a space or space record by URI"
        aria-invalid={bad || undefined}
        spellCheck={false}
        autoCapitalize="none"
        value={v}
        onChange={(e) => {
          setV(e.target.value)
          setBad(false)
        }}
      />
      <button className="cx-btn">Open</button>
    </form>
  )
}

const alpha = (
  <Chip k="violet" glyph={false}>
    alpha
  </Chip>
)

export function Spaces() {
  const on = useSpacesOn()
  if (on.data === undefined) return on.error ? <ErrorState error={on.error} retry={on.reload} /> : <Loading />
  if (!on.data)
    return (
      <>
        <PageHead title={<>Spaces {alpha}</>} />
        <Banners
          items={[
            {
              id: 'off',
              tone: 'info',
              title: 'Spaces is off on this server',
              desc: (
                <>
                  Start it with <span className="mono">--spaces</span> to host spaces and space repos. It’s an alpha that changes upstream every week, so leave it off unless you’re testing against it.
                </>
              ),
            },
          ]}
        />
      </>
    )
  return <SpacesOn />
}

function SpacesOn() {
  const [sort, setSort] = useState<Sort>('activity')
  const [cursor, setCursor] = useState<string>()
  const l = useAdminQuery<ListOut>({
    key: K.spacesList({ sort, cursor }),
    fn: (signal) => admin('vlpds.admin.listSpaces', { params: { sort, limit: PAGE, cursor }, signal }),
    poll: 60_000,
    keep: true,
  })
  const health = spacesStatusQ.use()
  const { view } = useClusterView()
  const d = l.data
  if (d) lastList = d.spaces
  const offset = Number(cursor ?? 0)
  const color = (n: string) => view?.nodes.find((x) => x.node === n)?.color

  const banners: BannerSpec[] = []
  if (d?.unreachableNodes?.length) banners.push({ id: 'unreach', tone: 'warn', title: `${d.unreachableNodes.join(', ')} didn't answer`, desc: 'Spaces whose authority is on those nodes are missing.' })
  if (d?.truncated) banners.push({ id: 'trunc', tone: 'warn', title: 'More spaces than one scan holds', desc: 'Totals and the list cover the first 2,000 spaces per node.' })
  for (const h of health.data ?? []) {
    const r = h.status?.revocations
    if (r && (!r.loaded || !r.fresh)) banners.push({ id: `rev-${h.node}`, tone: 'err', title: `${h.node}: revocation list ${r.loaded ? 'stale' : 'not read yet'}`, desc: 'Credential reads wait for it. Check the bucket.' })
  }

  const cols: Col<SpaceRow>[] = [
    {
      id: 'space',
      label: 'Space',
      render: (s) => (
        <span title={s.uri}>
          <span className="muted mono sm">{s.spaceType} /</span> <b>{s.skey}</b>
        </span>
      ),
    },
    { id: 'auth', label: 'Authority', render: (s) => <Who did={s.authority} handle={s.handle} /> },
    { id: 'rw', label: 'Read / write', render: (s) => <span className="t2">{s.readPolicy} / {s.writePolicy}</span> },
    { id: 'app', label: 'App', render: (s) => <span className="mono sm t2">{s.appAccess}</span> },
    { id: 'm', label: 'Members', r: true, render: (s) => <span className="mono">{s.members > d!.countCap ? `${fmtNum(d!.countCap)}+` : fmtNum(s.members)}</span> },
    { id: 'w', label: 'Writers', r: true, render: (s) => <span className="mono">{fmtNum(s.writers)}</span> },
    { id: 'rec', label: 'Records', r: true, render: (s) => <span className="mono">{fmtNum(s.records)}</span> },
    { id: 'last', label: 'Last write', r: true, render: (s) => when(s.lastActivityUs ? s.lastActivityUs / 1000 : null) },
    { id: 'st', label: 'State', render: (s) => <StateChip s={s} /> },
  ]

  return (
    <>
      <PageHead
        title={<>Spaces {alpha}</>}
        sub={
          <>
            <span>private, member-only repos hosted by their authority</span>
            <span>metadata only: reading a record needs a reason and is audited</span>
          </>
        }
        updated={l.at}
        actions={<OpenSpace />}
      />
      <Banners items={banners} />
      <Tiles
        boxed
        tiles={[
          { label: 'Spaces hosted here', right: d?.totals.takendown ? `${fmtNum(d.totals.takendown)} taken down` : undefined, value: d ? fmtNum(d.totals.spaces) : '—' },
          { label: 'Space repos stored here', right: d?.totals.foreignSpaces ? `+ in ${fmtNum(d.totals.foreignSpaces)} spaces elsewhere` : undefined, value: d ? fmtNum(d.totals.spaceRepos) : '—' },
          { label: 'Members', value: d ? fmtNum(d.totals.members) : '—' },
          { label: 'Writers', value: d ? fmtNum(d.totals.writers) : '—' },
          { label: 'Space records stored here', value: d ? fmtNum(d.totals.records) : '—' },
        ]}
      />
      <Panel className="cx-mt" title="Health" src={<Src>getSpacesStatus · every node · 10 s</Src>} foot="Alerts: VlpdsSpaceOutboxBacklog, VlpdsSpaceNotifyFanoutFailing, revocations past 90% of the cap.">
        {health.data ? (
          <DataTable
            compact
            rows={health.data}
            rowKey={(h) => h.node}
            cols={[
              {
                id: 'n',
                label: 'Node',
                render: (h) => (
                  <span className="cx-cellid">
                    <Swatch color={color(h.node)} />
                    <span className="mono">{h.node}</span>
                  </span>
                ),
              },
              ...(
                [
                  ['Notify outbox', (s) => [s.outbox.rows, s.outbox.max]],
                  ['Fan-out pending', (s) => [s.fanout.pending, s.fanout.queueMax]],
                  ['Revocations', (s) => [s.revocations.entries, s.revocations.hardCap]],
                  ['Credential cache', (s) => [s.credentialCache.entries, s.credentialCache.max]],
                ] as [string, (s: SpacesStatus) => [number, number]][]
              ).map(
                ([label, f], i): Col<HealthRow> => ({
                  id: `c${i}`,
                  label,
                  render: (h) => {
                    if (!h.status) return <Chip k="err">no answer</Chip>
                    const [v, max] = f(h.status)
                    return (
                      <span className="cx-cellid">
                        <Meter v={v} max={max} k={v / max > 0.9 ? 'err' : v / max > 0.5 ? 'warn' : 'ok'} />
                        <span className="mono sm">
                          {fmtNum(v)} <span className="muted">/ {fmtNum(max)}</span>
                        </span>
                      </span>
                    )
                  },
                }),
              ),
              {
                id: 'rv',
                label: 'Revocation list',
                render: (h) => {
                  const r = h.status?.revocations
                  if (!r) return null
                  return !r.loaded ? <Chip k="err">not read</Chip> : !r.fresh ? <Chip k="err">stale</Chip> : r.saturated ? <Chip k="warn">saturated</Chip> : <Chip k="ok">fresh</Chip>
                },
              },
            ]}
          />
        ) : health.error ? (
          <ErrorState error={health.error} retry={spacesStatusQ.refresh} />
        ) : (
          <Loading />
        )}
      </Panel>
      <Panel
        className="cx-mt"
        title="Spaces hosted here"
        src={<Src>listSpaces · on change</Src>}
        right={
          <>
            <Seg
              label="Sort by"
              value={sort}
              onChange={(v) => {
                setSort(v)
                setCursor(undefined)
              }}
              options={SORTS.map((s) => ({ v: s.v, label: s.label }))}
            />
            <Link className="cx-btn sm" to="/admin/moderation?tab=audit&scope=spaces">
              Audit log
            </Link>
          </>
        }
        foot={
          d && (d.cursor || offset > 0) ? (
            <span className="cx-form-row" style={{ justifyContent: 'flex-end' }}>
              <span className="muted">
                {offset + 1}–{offset + d.spaces.length} of {fmtNum(d.count)}
              </span>
              <button type="button" className="cx-btn sm" disabled={offset === 0 || l.loading} onClick={() => setCursor(offset - PAGE > 0 ? String(offset - PAGE) : undefined)}>
                Previous
              </button>
              <button type="button" className="cx-btn sm" disabled={!d.cursor || l.loading} onClick={() => setCursor(d.cursor)}>
                Next
              </button>
            </span>
          ) : (
            'Spaces whose authority is an account here. Records counts only space repos stored here: a writer on another PDS keeps its own.'
          )
        }
      >
        {d ? (
          <DataTable
            rows={d.spaces}
            cols={cols}
            rowKey={(s) => s.uri}
            open={(s) => ({ type: 'space', id: s.uri })}
            dim={(s) => s.takendown || !!s.deletedAt}
            empty={<div className="cx-empty">No spaces yet. A space shows up here once an account on this PDS creates one.</div>}
            label="Spaces"
          />
        ) : l.error ? (
          <ErrorState error={l.error} retry={l.reload} />
        ) : (
          <Loading />
        )}
      </Panel>
    </>
  )
}

// ---------------------------------------------------------------- one space

function RecordBrowser({ space, repo, reason, onDone }: { space: string; repo: string; reason: string; onDone: () => void }) {
  const [rows, setRows] = useState<SpaceRecord[]>()
  const [cursor, setCursor] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [open, setOpen] = useState<string>()
  const page = async (cur?: string) => {
    setBusy(true)
    setError(undefined)
    try {
      const r: { records: SpaceRecord[]; cursor?: string } = await admin('vlpds.admin.listSpaceRecords', { params: { space, repo, reason, cursor: cur, limit: 50 } })
      setRows((x) => (cur ? [...(x ?? []), ...r.records] : r.records))
      setCursor(r.cursor)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  useEffect(() => {
    page()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  if (error) return <ErrorState error={error} retry={() => page(cursor)} />
  if (!rows) return <Loading label="Reading (audited)…" />
  if (!rows.length) return <Empty>No records.</Empty>
  return (
    <>
      <div className="cx-tw">
        <table className="cx-t compact">
          <tbody>
            {rows.map((r) => (
              <RecordRow
                key={r.uri}
                r={r}
                path={r.uri.slice(`${space}/${repo}/`.length)}
                open={open === r.uri}
                toggle={() => setOpen((o) => (o === r.uri ? undefined : r.uri))}
                moderated={() => {
                  setRows((x) => x?.map((y) => (y.uri === r.uri ? { ...y, takendown: !y.takendown } : y)))
                  onDone()
                }}
                did={repo}
              />
            ))}
          </tbody>
        </table>
      </div>
      {cursor && (
        <div style={{ padding: '8px 12px' }}>
          <button type="button" className="cx-btn sm" disabled={busy} onClick={() => page(cursor)}>
            Next page (another audited read)
          </button>
        </div>
      )}
    </>
  )
}

function RecordRow({ r, path, open, toggle, moderated, did }: { r: SpaceRecord; path: string; open: boolean; toggle: () => void; moderated: () => void; did: string }) {
  return (
    <>
      <tr>
        <td className="mono sm">
          <Link to={lookupUrl(r.uri)} title={r.uri}>
            {path}
          </Link>
        </td>
        <td>
          <Chip k={subjectTone(r.takendown)![0]}>{subjectTone(r.takendown)![1]}</Chip>
        </td>
        <td className="r">
          <span className="cx-cellid end">
            <button type="button" className="cx-btn sm quiet" aria-expanded={open} onClick={toggle}>
              {open ? 'Hide' : 'Show'}
            </button>
            <button type="button" className={`cx-btn sm${r.takendown ? '' : ' danger'}`} onClick={() => moderate({ kind: 'record', did, uri: r.uri }, r.takendown, moderated)}>
              {r.takendown ? 'Restore…' : 'Take down…'}
            </button>
          </span>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={3} style={{ whiteSpace: 'normal', height: 'auto' }}>
            <Json value={r.value} />
          </td>
        </tr>
      )}
    </>
  )
}

function readRecords(handle: string, start: (reason: string) => void) {
  confirmAction({
    tone: 'warn',
    primary: true,
    title: `Read ${handle}'s records in this space?`,
    items: ['Space records are private to the space’s members.', 'Each page you read is written to the audit log with your reason.'],
    fields: [{ id: 'reason', label: 'Reason (kept in the audit log)', required: true, type: 'textarea' }],
    action: 'Read records',
    call: 'vlpds.admin.listSpaceRecords (audited)',
    run: async (v) => start(String(v.reason).trim()),
  })
}

function removeRegistration(authority: string, space: string, service: string, done: () => void) {
  confirmAction({
    tone: 'warn',
    title: 'Remove this notify registration?',
    items: [
      <span className="mono sm" style={{ overflowWrap: 'anywhere' }}>{service}</span>,
      'The service stops getting this space’s notifies at once.',
      'It can register again with a credential for the space: take the space down to keep it out.',
    ],
    fields: [{ id: 'reason', label: 'Reason (kept in the audit log)', required: true, type: 'textarea' }],
    action: 'Remove',
    call: 'vlpds.admin.removeSpaceRegistration',
    run: (v) =>
      mutate({
        run: () => admin('vlpds.admin.removeSpaceRegistration', { body: { did: authority, space, service, reason: String(v.reason).trim() } }),
        changes: [{ kind: 'space', id: space }],
      }).then(done),
    done: 'Registration removed',
  })
}

function SpaceAudit({ space, entries }: { space: string; entries: Audit[] }) {
  const what = (e: Audit) => {
    const s = e.subject
    if (!s) return '—'
    if (s.kind === 'space') return e.detail?.service ? `registration ${e.detail.service}` : 'the space'
    if (s.kind === 'spaceRepo') return `repo of ${shortDid(s.did)}`
    return s.uri?.startsWith(`${space}/`) ? s.uri.slice(space.length + 1) : (s.uri ?? s.did)
  }
  if (!entries.length) return <Empty>Nothing yet.</Empty>
  return (
    <div className="cx-tw">
      <table className="cx-t compact">
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td>{ago(Date.parse(e.at))}</td>
              <td>
                <Chip k={e.action === 'takedown' || e.action.endsWith('.remove') ? 'err' : 'plain'} glyph={e.action === 'takedown'}>
                  {e.detail?.method ?? e.action}
                </Chip>
              </td>
              <td className="mono sm trunc" style={{ maxWidth: 220 }} title={what(e)}>
                {what(e)}
              </td>
              <td className="sm" title={[e.ip, authName(e.auth)].filter(Boolean).join(' · ')}>
                {e.actor}
              </td>
              <td className="sm t2 trunc" style={{ maxWidth: 240 }} title={e.reason}>
                {e.reason ?? '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

registerDetail('space', {
  kind: 'Space',
  section: 'spaces',
  use: (uri, mode) => {
    const p = parseSpaceUri(uri)
    const l = useAdminQuery<SpaceInfo>({
      key: K.space(uri),
      fn: (signal) => admin('vlpds.admin.getSpaceInfo', { params: { did: p!.authority, uri: p!.space }, signal }),
      enabled: !!p && !p.record,
      poll: 60_000,
    })
    const auditL = useAudit({ space: uri, limit: 50 })
    const audit = { ...auditL, data: auditL.data && { entries: auditL.data as unknown as Audit[] } }
    const [browse, setBrowse] = useState<{ repo: string; reason: string; n: number }>()
    const reload = () => {
      l.reload()
      audit.reload()
    }
    if (!p || p.record) return { title: <span className="mono sm">{uri}</span>, body: null, missing: 'Not a space URI (at://authority/space/type/key).' }
    if (l.error) return { title: spaceLabel(uri), body: <ErrorState error={l.error} retry={l.reload} /> }
    const d = l.data
    if (!d) return { title: spaceLabel(uri), body: null, loading: true }
    const s = d.space
    const page = mode === 'page'
    const localRecords = d.writers.reduce((t, w) => t + (w.local ? (w.records ?? 0) : 0), 0)
    const banners: BannerSpec[] = []
    if (s.takendown) banners.push({ id: 'td', tone: 'err', title: 'Taken down', desc: 'No credentials, no listing of its writers, no notify registrations; members’ notifies are dropped.' })
    if (s.deletedAt) banners.push({ id: 'del', tone: 'warn', title: `Deleted by its owner ${ago(Date.parse(s.deletedAt))}`, desc: 'The row stays so credential requests get SpaceDeleted.' })
    const writers = (
      <Sec title="Writers" digest={`${d.writers.length}${d.moreWriters ? '+' : ''} · as their hosts last reported`} open flush>
        {d.writers.length ? (
          <DataTable
            compact
            rows={d.writers}
            rowKey={(w) => w.did}
            cols={[
              { id: 'w', label: 'Writer', render: (w) => <Who did={w.did} handle={w.handle} /> },
              {
                id: 'r',
                label: 'Records',
                r: true,
                render: (w) =>
                  w.local ? (
                    <span className="cx-cellid end">
                      <span className="mono">{fmtNum(w.records)}</span>
                      {!!w.takendownRecords && <Chip k="err">{w.takendownRecords} down</Chip>}
                    </span>
                  ) : (
                    <span className="muted" title="Stored on another PDS">
                      elsewhere
                    </span>
                  ),
              },
              { id: 'l', label: 'Last write', render: (w) => when(w.repoRev?.at) },
              ...(page ? [{ id: 'rev', label: 'spaceRev', render: (w: Writer) => <span className="mono sm t2">{w.spaceRev?.rev ?? '—'}</span> }, { id: 'h', label: 'Hash', render: (w: Writer) => <span className="mono sm t2" title="First 8 bytes of the set hash">{w.hash}</span> }] : []),
              {
                id: 'a',
                label: '',
                r: true,
                render: (w) =>
                  w.local && (
                    <button type="button" className="cx-btn sm" onClick={() => readRecords(w.handle ? `@${w.handle}` : shortDid(w.did), (reason) => setBrowse({ repo: w.did, reason, n: Date.now() }))}>
                      Records…
                    </button>
                  ),
              },
            ]}
          />
        ) : (
          <Empty>No writes yet.</Empty>
        )}
      </Sec>
    )
    const browser = browse && (
      <Sec
        title={`Records of ${d.writers.find((w) => w.did === browse.repo)?.handle ? `@${d.writers.find((w) => w.did === browse.repo)!.handle}` : shortDid(browse.repo)}`}
        digest="audited read"
        right={
          <button type="button" className="cx-btn sm quiet" onClick={() => setBrowse(undefined)}>
            Close
          </button>
        }
        open
        flush
      >
        <RecordBrowser key={browse.n} space={s.uri} repo={browse.repo} reason={browse.reason} onDone={reload} />
      </Sec>
    )
    const members = (
      <Sec title="Members" digest={`${d.members.length}${d.moreMembers ? '+' : ''}`} open flush>
        {d.members.length ? (
          <DataTable
            compact
            rows={d.members}
            rowKey={(m) => m.did}
            cols={[
              { id: 'm', label: 'Member', render: (m) => <Who did={m.did} handle={m.handle} /> },
              {
                id: 'g',
                label: 'Grants',
                render: (m) => (
                  <span className="cx-cellid">
                    {m.read && <Chip k="plain" glyph={false}>read</Chip>}
                    {m.write && <Chip k="acc">write</Chip>}
                  </span>
                ),
              },
            ]}
          />
        ) : (
          <Empty>No members. Writers on a managing-app or public policy needn’t be on the list.</Empty>
        )}
      </Sec>
    )
    const regs = (
      <Sec title="Notify registrations" digest={plural(d.registrations.length, 'service')} open={page || d.registrations.length > 0} flush>
        {d.registrations.length ? (
          <DataTable
            compact
            rows={d.registrations}
            rowKey={(r) => r.service}
            cols={[
              { id: 's', label: 'Service', render: (r) => <Copy text={r.service}>{r.service.length > 32 ? `${r.service.slice(0, 32)}…` : r.service}</Copy> },
              { id: 'h', label: 'Host', render: (r) => <span className="mono sm">{r.host ?? '—'}</span> },
              { id: 'e', label: 'Expires', render: (r) => (r.expired ? <Chip k="idle">expired</Chip> : r.expiresAt ? ago(Date.parse(r.expiresAt)) : '—') },
              {
                id: 'x',
                label: '',
                r: true,
                render: (r) => (
                  <button type="button" className="cx-btn sm danger" onClick={() => removeRegistration(s.authority, s.uri, r.service, reload)}>
                    Remove…
                  </button>
                ),
              },
            ]}
          />
        ) : (
          <Empty>No service is registered for this space’s notifies.</Empty>
        )}
      </Sec>
    )
    const activity = (
      <Sec title="Recent activity" digest="newest spaceRev per writer" open={page}>
        {d.activity.length ? (
          <KV rows={d.activity.map((a) => [when(a.at), <span key={a.spaceRev}><span className="mono sm">{a.spaceRev}</span> <span className="muted">by</span> <Copy text={a.writer}>{shortDid(a.writer)}</Copy></span>] as [ReactNode, ReactNode])} />
        ) : (
          <Empty>Nothing sequenced yet.</Empty>
        )}
      </Sec>
    )
    const downs = (
      <Sec title="Taken-down records" digest={`${d.takendownRecords.length}`} open={d.takendownRecords.length > 0} flush>
        {d.takendownRecords.length ? (
          <DataTable
            compact
            rows={d.takendownRecords}
            rowKey={(r) => r.uri}
            cols={[
              { id: 'u', label: 'Record', render: (r) => <span className="mono sm" title={r.uri}>{r.uri.slice(s.uri.length + 1)}</span> },
              {
                id: 'a',
                label: '',
                r: true,
                render: (r) => (
                  <button type="button" className="cx-btn sm" onClick={() => moderate({ kind: 'record', did: r.did, uri: r.uri }, true, reload)}>
                    Restore…
                  </button>
                ),
              },
            ]}
          />
        ) : (
          <Empty>None.</Empty>
        )}
      </Sec>
    )
    const auditSec = (
      <Sec title="Audit log" digest="takedowns, record reads, registration removals" open={page} flush>
        {audit.data ? <SpaceAudit space={s.uri} entries={audit.data.entries} /> : audit.error ? <ErrorState error={audit.error} retry={audit.reload} /> : <Loading />}
      </Sec>
    )
    const info = (
      <Sec title="Space" digest={`${s.readPolicy} read · ${s.writePolicy} write`} open>
        <KV
          rows={[
            ['URI', <Copy text={s.uri}>{`at://${shortDid(s.authority)}/space/${s.spaceType}/${s.skey}`}</Copy>],
            ['Authority', <Who did={s.authority} handle={s.handle} />],
            ['Read / write', `${s.readPolicy} / ${s.writePolicy}`],
            ['App access', <span className="mono">{s.appAccess}</span>],
            ['Created', ago(Date.parse(s.createdAt))],
            ['State', <StateChip s={s} />],
          ]}
        />
        <div className="cx-form-row" style={{ marginTop: 10 }}>
          <button type="button" className={`cx-btn sm${s.takendown ? '' : ' danger'}`} onClick={() => moderate({ kind: 'space', did: s.authority, uri: s.uri }, s.takendown, reload)}>
            {s.takendown ? 'Restore space…' : 'Take down space…'}
          </button>
          <Link className="cx-btn sm quiet" to={accountUrl(s.authority)}>
            Authority’s account
          </Link>
        </div>
      </Sec>
    )
    return {
      title: (
        <>
          <span className="muted">{s.spaceType} /</span> {s.skey}
        </>
      ),
      chip: <StateChip s={s} />,
      updated: l.at,
      foot: <Src>getSpaceInfo · getAuditLog</Src>,
      body: (
        <>
          {banners.length > 0 && <Banners items={banners} />}
          <Strip items={[['members', `${fmtNum(d.members.length)}${d.moreMembers ? '+' : ''}`], ['writers', `${fmtNum(d.writers.length)}${d.moreWriters ? '+' : ''}`], ['records here', fmtNum(localRecords)], ['registrations', fmtNum(d.registrations.length)]]} />
          {page ? (
            <div className="cols">
              <div className="cx-stack">
                {info}
                {writers}
                {browser}
                {members}
              </div>
              <div className="cx-stack">
                {activity}
                {regs}
                {downs}
                {auditSec}
              </div>
            </div>
          ) : (
            <>
              {info}
              {writers}
              {browser}
              {members}
              {regs}
              {downs}
              {activity}
              {auditSec}
            </>
          )}
        </>
      ),
    }
  },
})

/** Old links (/admin/spaces/space?uri=…) show the space's full page. */
export function SpaceByUri() {
  const uri = useSearch().get('uri') ?? ''
  return <DetailPage type="space" id={uri} />
}
