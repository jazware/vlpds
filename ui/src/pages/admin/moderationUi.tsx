import { useEffect, useRef, useState, type ReactNode } from 'react'
import { confirmAction, FormDialog, openDialog } from '../../components/console/dialogs'
import { registerDetail } from '../../components/console/Drawer'
import { Chip, Copy, GLYPH, Json, KV, Meter, RRow, Sec, Spinner, Src, Strip } from '../../components/console/kit'
import { openPanel, panelParam } from '../../components/console/nav'
import { registerPalette } from '../../components/console/Palette'
import { toast } from '../../components/console/toast'
import { ago, auditAction, auditSubjectText, authName, authShort, fmtBytes, plural } from '../../lib/console/fmt'
import {
  auditSeen,
  isOperatorSubject,
  CASE_STATUSES,
  CASE_TONE,
  createCase,
  fmtGB,
  getAuditLog,
  getCase,
  getSubject,
  listCases,
  listCasesAbout,
  moderate,
  resolveSubject,
  SEMANTICS,
  setBlobQuota,
  shortUri,
  spaceRecordParts,
  subjectQuery,
  updateCase,
  useModVersion,
  type AuditEntry,
  type BlobView,
  type Case,
  type Kind,
  type Quota,
  type SubjectDetail,
  type SubjectRef,
} from '../../lib/console/moderation'
import { openCasesPoll } from '../../lib/console/polls'
import { useAction, useLoad } from '../../lib/hooks'
import { Link, navigate, useSearch } from '../../lib/router'
import { admin, errText } from '../../lib/xrpc'
import { Ops } from './accountDetail'
import { AuditAction, auditLinks, OperatorSubjectLink } from './auditUi'
import { openAccount, Who } from './peopleUi'
import { spaceUrl } from './Spaces'

// Moderation's slide-overs (case, subject, audit entry), its dialogs and ⌘K entries.

const ISO = (s: string) => Date.parse(s)

// ---------------------------------------------------------------- subjects

/** A subject in one line: whose, and which record, blob or space. */
export function SubjectLabel({ s, handle }: { s: SubjectRef; handle?: string | null }) {
  if (s.kind === 'account') return <Who did={s.did} handle={handle} />
  if (s.kind === 'blob')
    return (
      <span className="cx-cellid" style={{ minWidth: 0 }}>
        <Who did={s.did} handle={handle} />
        <span className="mono sm t2 trunc" title={s.cid}>
          {s.cid?.slice(0, 18)}…
        </span>
      </span>
    )
  return (
    <span className="cx-cellid" style={{ minWidth: 0 }}>
      <Who did={s.did} handle={handle} />
      <span className="mono sm t2 trunc" title={s.uri}>
        {shortUri(s.uri ?? '')}
      </span>
    </span>
  )
}

/** Opens a subject's slide-over; actions in it are filed under `caseId`. */
export function reviewSubject(s: SubjectRef | string, caseId?: string) {
  const q = typeof s === 'string' ? s : subjectQuery(s)
  const sp = new URLSearchParams(location.search)
  sp.set('open', panelParam('subject', q))
  if (caseId) sp.set('case', caseId)
  navigate(`${location.pathname}?${sp}`, { replace: !!new URLSearchParams(location.search).get('open') })
}

/** Takes a subject down or restores it, after a typed confirm and a reason. */
export function confirmModerate(o: { subject: SubjectRef; restore: boolean; handle?: string; caseId?: string }) {
  const s = o.subject
  const kind = (s.kind === 'spaceRepo' ? 'record' : s.kind) as Kind
  return confirmAction({
    tone: o.restore ? 'warn' : 'err',
    title: o.restore ? `Restore this ${kind}?` : `Take down this ${kind}?`,
    items: [
      <span className="mono sm" style={{ wordBreak: 'break-all' }}>
        {subjectQuery(s)}
      </span>,
      ...(o.restore ? ['Lifts the takedown and puts any quarantined bytes back.'] : SEMANTICS[kind]),
      o.caseId ? (
        <>
          Filed under case <span className="mono">{o.caseId}</span>.
        </>
      ) : (
        'Not filed under a case.'
      ),
    ],
    fields: [{ id: 'reason', label: 'Reason (kept in the audit log)', type: 'textarea', required: true }],
    word: o.restore ? undefined : (o.handle ?? s.did),
    action: o.restore ? 'Restore' : 'Take down',
    primary: o.restore,
    call: `vlpds.admin.moderate {kind: ${kind}, action: ${o.restore ? 'restore' : 'takedown'}${o.caseId ? ', caseId' : ''}} → owner node`,
    run: (v) => moderate(s, o.restore, String(v.reason), o.caseId),
    done: o.restore ? 'Restored' : 'Taken down',
  })
}

export function ModButton({ s, applied, handle, caseId, label }: { s: SubjectRef; applied: boolean; handle?: string; caseId?: string; label?: string }) {
  return (
    <button type="button" className={`cx-btn sm${applied ? '' : ' danger'}`} onClick={() => confirmModerate({ subject: s, restore: applied, handle, caseId })}>
      {applied ? 'Restore…' : `Take down${label ? ` ${label}` : ''}…`}
    </button>
  )
}

/** Whether the subject a detail was loaded for is taken down. */
export function appliedOf(d: SubjectDetail | undefined, s: SubjectRef): boolean | undefined {
  if (!d) return undefined
  if (s.kind === 'account') return d.account.takedown.applied
  if (s.kind === 'blob') return d.blob?.takendown
  if (s.kind === 'space') return d.space?.takendown
  if (s.kind === 'record') return d.record?.takendown ?? d.spaceRecord?.takendown
  return undefined
}

// ---------------------------------------------------------------- dialogs

export function newCaseDialog(subject?: string) {
  openDialog((close) => <NewCase close={close} subject={subject} />)
}

function NewCase({ close, subject }: { close: () => void; subject?: string }) {
  const [source, setSource] = useState('')
  const [note, setNote] = useState('')
  const [subj, setSubj] = useState(subject ?? '')
  const go = useAction(async () => {
    let subjects: SubjectRef[] | undefined
    if (subj.trim()) {
      const r = await resolveSubject(subj.trim())
      subjects = [{ kind: r.kind, did: r.did, uri: r.uri, cid: r.cid }]
    }
    const c = await createCase(source.trim(), note.trim(), subjects)
    close()
    toast(`Opened case ${c.id}`)
    navigate(`/admin/moderation?open=${encodeURIComponent(panelParam('case', c.id))}`)
  })
  return (
    <FormDialog title="New case" call="vlpds.admin.createCase" action="Open case" busy={go.busy} disabled={!source.trim()} error={go.error} onSubmit={() => go.run()} onCancel={close}>
      <p className="t2" style={{ margin: 0 }}>
        One per notice or report: who sent it and what it claims.
      </p>
      <div>
        <label className="cx-lbl" htmlFor="nc-src">
          Source
        </label>
        <input id="nc-src" className="cx-inp" autoFocus value={source} onChange={(e) => setSource(e.target.value)} placeholder="DMCA notice from Example Studios, by email" />
      </div>
      <div>
        <label className="cx-lbl" htmlFor="nc-subj">
          First subject (optional)
        </label>
        <input id="nc-subj" className="cx-inp mono" value={subj} onChange={(e) => setSubj(e.target.value)} placeholder="bsky.app URL, at:// URI, handle, DID, DID + blob CID" spellCheck={false} />
      </div>
      <div>
        <label className="cx-lbl" htmlFor="nc-note">
          First note (optional)
        </label>
        <textarea id="nc-note" className="cx-inp" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
    </FormDialog>
  )
}

function quotaDialog(did: string, q: Quota) {
  openDialog((close) => <QuotaForm did={did} q={q} close={close} />)
}

function QuotaForm({ did, q, close }: { did: string; q: Quota; close: () => void }) {
  const [gb, setGb] = useState(q.override.bytes !== undefined ? String(q.override.bytes / 1e9) : '')
  const [perDay, setPerDay] = useState(q.override.uploadsPerDay !== undefined ? String(q.override.uploadsPerDay) : '')
  const [reason, setReason] = useState('')
  const [reset, setReset] = useState(false)
  const save = useAction(async () => {
    const v: { bytes?: number; uploadsPerDay?: number; reason?: string } = { reason: reason.trim() || undefined }
    if (!reset) {
      if (gb.trim() !== '') v.bytes = Math.round(Number(gb) * 1e9)
      if (perDay.trim() !== '') v.uploadsPerDay = Math.round(Number(perDay))
    }
    await setBlobQuota(did, v)
    close()
    toast(reset ? 'Quota back to the defaults' : 'Quota saved')
  })
  return (
    <FormDialog title="Blob quota" icon="◔" call="vlpds.admin.setBlobQuota → owner node" action="Save quota" busy={save.busy} error={save.error} onSubmit={() => save.run()} onCancel={close}>
      <div className="cx-form-row">
        <div style={{ flex: 1 }}>
          <label className="cx-lbl" htmlFor="q-gb">
            Bytes (GB)
          </label>
          <input id="q-gb" className="cx-inp mono" type="number" min="0" step="any" disabled={reset} value={gb} onChange={(e) => setGb(e.target.value)} placeholder={`default ${fmtGB(q.defaults.bytes)}`} />
        </div>
        <div style={{ flex: 1 }}>
          <label className="cx-lbl" htmlFor="q-day">
            Uploads per day
          </label>
          <input id="q-day" className="cx-inp mono" type="number" min="0" step="1" disabled={reset} value={perDay} onChange={(e) => setPerDay(e.target.value)} placeholder={`default ${q.defaults.uploadsPerDay}`} />
        </div>
      </div>
      <p className="muted sm" style={{ margin: 0 }}>
        Blank keeps the server default. 0 is unlimited.
      </p>
      <label className="cx-form-row" style={{ cursor: 'pointer' }}>
        <input type="checkbox" checked={reset} onChange={(e) => setReset(e.target.checked)} /> Back to the defaults
      </label>
      <div>
        <label className="cx-lbl" htmlFor="q-why">
          Reason (audit log)
        </label>
        <input id="q-why" className="cx-inp" value={reason} onChange={(e) => setReason(e.target.value)} />
      </div>
    </FormDialog>
  )
}

// ---------------------------------------------------------------- blob preview

/** Fetches nothing until asked; images blurred until revealed; video never autoplays. */
function SafePreview({ did, b }: { did: string; b: BlobView }) {
  const [url, setUrl] = useState<string>()
  const [reveal, setReveal] = useState(false)
  const urlRef = useRef<string | undefined>(undefined)
  useEffect(
    () => () => {
      if (urlRef.current) URL.revokeObjectURL(urlRef.current)
    },
    [],
  )
  const load = useAction(async () => {
    const r: Response = await admin('com.atproto.sync.getBlob', { params: { did, cid: b.cid }, raw: true })
    const u = URL.createObjectURL(await r.blob())
    urlRef.current = u
    setUrl(u)
  })
  const mime = b.mimeType ?? ''
  const image = mime.startsWith('image/')
  const video = mime.startsWith('video/')
  if (!b.stored && !b.quarantined) return <div className="cxp-preview empty">No bytes stored</div>
  if (!url)
    return (
      <div className="cxp-preview empty">
        <button type="button" className="cx-btn sm" onClick={() => load.run()} disabled={load.busy}>
          {load.busy && <Spinner />}
          {image ? 'Load preview (blurred)' : video ? 'Load video (paused)' : 'Load file'}
        </button>
        {!!load.error && <span className="s-err sm">{errText(load.error)}</span>}
      </div>
    )
  if (image)
    return (
      <button type="button" className={`cxp-preview${reveal ? '' : ' blurred'}`} onClick={() => setReveal((v) => !v)} aria-label={reveal ? 'Blur image' : 'Reveal image'}>
        <img src={url} alt="" />
        {!reveal && <span className="cxp-reveal">Click to reveal</span>}
      </button>
    )
  if (video)
    return (
      <div className={`cxp-preview${reveal ? '' : ' blurred'}`}>
        <video src={url} controls={reveal} preload="metadata" playsInline muted />
        {!reveal && (
          <button type="button" className="cxp-reveal" onClick={() => setReveal(true)}>
            Click to reveal
          </button>
        )}
      </div>
    )
  return (
    <div className="cxp-preview empty">
      <a className="cx-btn sm" href={url} download={b.cid}>
        Download
      </a>
    </div>
  )
}

function BlobBlock({ did, b, handle, caseId }: { did: string; b: BlobView; handle: string; caseId?: string }) {
  const purged = !!b.takedown?.purgedAtMs
  return (
    <div className="cxp-blob">
      <SafePreview did={did} b={b} />
      <div style={{ minWidth: 0 }}>
        <KV
          rows={[
            ['CID', <Copy text={b.cid}>{`${b.cid.slice(0, 24)}…`}</Copy>],
            ['Type', `${b.mimeType ?? 'unknown'}${b.size !== undefined ? ` · ${fmtBytes(b.size)}` : ''}`],
            [
              'State',
              <span className="cx-form-row" style={{ gap: 6 }}>
                {b.takendown ? <Chip k="err">taken down</Chip> : <Chip k="ok">served</Chip>}
                {b.quarantined && <Chip k="warn">quarantined</Chip>}
                {purged && <Chip k="err">bytes purged</Chip>}
                {!b.stored && !b.quarantined && !purged && <Chip k="idle">not stored</Chip>}
              </span>,
            ],
            ...(b.takendown && b.purgeAfterMs && !purged ? [['Purge', `deleted ${ago(b.purgeAfterMs)} unless restored`] as [string, ReactNode]] : []),
          ]}
        />
        <div style={{ marginTop: 8 }}>
          <ModButton s={{ kind: 'blob', did, cid: b.cid }} applied={b.takendown} handle={handle} caseId={caseId} label="blob" />
        </div>
      </div>
    </div>
  )
}

function RecordJson({ value }: { value: unknown }) {
  const [show, setShow] = useState(false)
  return (
    <>
      <button type="button" className="cx-btn sm" onClick={() => setShow((v) => !v)} aria-expanded={show}>
        {show ? 'Hide record JSON' : 'Show record JSON'}
      </button>
      {show && <Json value={value} />}
    </>
  )
}

function SpaceRecordRead({ did, uri }: { did: string; uri: string }) {
  const [value, setValue] = useState<unknown>()
  if (value !== undefined) return <Json value={value} />
  return (
    <button
      type="button"
      className="cx-btn sm"
      onClick={() =>
        confirmAction({
          tone: 'warn',
          primary: true,
          title: 'Read this space record?',
          items: ['Space records are private to the space’s members.', 'Reading one is written to the audit log with your reason.'],
          fields: [{ id: 'reason', label: 'Reason (kept in the audit log)', type: 'textarea', required: true }],
          action: 'Read record',
          call: 'vlpds.admin.getSpaceRecord (audited)',
          run: async (v) => {
            const { space, collection, rkey } = spaceRecordParts(uri)
            const r: { value: unknown } = await admin('vlpds.admin.getSpaceRecord', { params: { space, repo: did, collection, rkey, reason: String(v.reason).trim() } })
            setValue(r.value ?? null)
          },
        })
      }
    >
      Read record…
    </button>
  )
}

// ---------------------------------------------------------------- subject slide-over

function CasePicker({ cases, value }: { cases?: Case[]; value?: string }) {
  const open = (cases ?? []).filter((c) => c.status !== 'dismissed')
  return (
    <div className="cx-form-row cxp-casepick">
      <label className="cx-lbl" htmlFor="cxp-case" style={{ margin: 0 }}>
        File actions under
      </label>
      <select
        id="cxp-case"
        className="cx-inp"
        value={value ?? ''}
        onChange={(e) => {
          const sp = new URLSearchParams(location.search)
          if (e.target.value) sp.set('case', e.target.value)
          else sp.delete('case')
          navigate(`${location.pathname}?${sp}`, { replace: true })
        }}
      >
        <option value="">No case</option>
        {value && !open.some((c) => c.id === value) && <option value={value}>{value}</option>}
        {open.map((c) => (
          <option key={c.id} value={c.id}>
            {c.source.slice(0, 60)} ({c.status})
          </option>
        ))}
      </select>
    </div>
  )
}

function quotaRows(q: Quota): [string, ReactNode][] {
  return [
    [
      'Stored',
      <span className="cx-form-row" style={{ gap: 8 }}>
        {fmtGB(q.bytes)} of {q.limitBytes ? fmtGB(q.limitBytes) : 'unlimited'}
        {q.limitBytes > 0 && <Meter v={q.bytes} max={q.limitBytes} k={q.over ? 'err' : q.bytes / q.limitBytes > 0.8 ? 'warn' : 'ok'} />}
      </span>,
    ],
    ['Uploads today', `${q.uploadsToday} of ${q.limitUploadsPerDay || 'unlimited'}`],
    ['Limits', q.override.bytes !== undefined || q.override.uploadsPerDay !== undefined ? 'custom for this account' : 'server defaults'],
  ]
}

registerDetail('subject', {
  kind: 'Moderation subject',
  section: 'moderation',
  use: (id, mode) => {
    const v = useModVersion()
    const caseId = useSearch().get('case') ?? undefined
    const res = useLoad(() => resolveSubject(id), [id])
    const r = res.data
    const det = useLoad(() => (r ? getSubject(r) : Promise.resolve(undefined)), [r?.did, r?.uri, r?.cid, v])
    const audit = useLoad(() => (r ? getAuditLog({ did: r.did, limit: 25 }) : Promise.resolve([])), [r?.did, v])
    const cases = useLoad(() => listCases(), [v])
    const about = useLoad(() => (r ? listCasesAbout(r.did, r.uri ?? r.cid) : Promise.resolve([])), [r?.did, r?.uri, r?.cid, v])
    if (res.error) return { title: <span className="mono">{id}</span>, body: null, missing: errText(res.error) }
    const d = det.data
    if (!r || !d) return { title: <span className="mono">{id}</span>, body: null, loading: !det.error, missing: det.error ? errText(det.error) : undefined }
    const s: SubjectRef = { kind: r.kind, did: r.did, uri: r.uri, cid: r.cid }
    const applied = appliedOf(d, s)
    const a = d.account
    const page = mode === 'page'
    const title =
      s.kind === 'account' ? (
        `@${a.handle}`
      ) : s.kind === 'blob' ? (
        <span className="mono">blob {s.cid?.slice(0, 16)}…</span>
      ) : (
        <span className="mono">{shortUri(s.uri ?? '')}</span>
      )
    const record = d.record && (
      <Sec title="Record" digest={d.record.exists ? (d.record.takendown ? 'hidden from record reads' : 'served') : 'not in this repo'} open>
        {!d.record.exists ? (
          <p className="t2" style={{ margin: 0 }}>
            No such record in this repo: deleted, or it never existed.
          </p>
        ) : (
          <>
            <KV rows={[['URI', <Copy text={d.record.uri}>{shortUri(d.record.uri)}</Copy>], ['CID', d.record.cid ? <Copy text={d.record.cid}>{`${d.record.cid.slice(0, 24)}…`}</Copy> : '—'], ['State', d.record.takendown ? <Chip k="err">hidden</Chip> : <Chip k="ok">served</Chip>]]} />
            <div className="cx-form-row" style={{ marginTop: 8 }}>
              <RecordJson value={d.record.value} />
              <ModButton s={s} applied={d.record.takendown} handle={a.handle} caseId={caseId} label="record" />
            </div>
          </>
        )}
      </Sec>
    )
    const blobs = !!d.record?.blobs?.length && (
      <Sec title="Blobs in this record" digest={`${d.record.blobs.length}`} open>
        <div className="cx-stack">
          {d.record.blobs.map((b) => (
            <BlobBlock key={b.cid} did={a.did} b={b} handle={a.handle} caseId={caseId} />
          ))}
        </div>
      </Sec>
    )
    const blob = d.blob && (
      <Sec title="Blob" digest={d.blob.takendown ? 'taken down' : 'served'} open>
        <BlobBlock did={a.did} b={d.blob} handle={a.handle} caseId={caseId} />
      </Sec>
    )
    const spaceRec = d.spaceRecord && (
      <Sec title="Space record" digest="private: reading it is audited" open>
        {!d.spaceRecord.exists ? (
          <p className="t2" style={{ margin: 0 }}>
            No such record in this repo: deleted, or it never existed.
          </p>
        ) : (
          <>
            <KV
              rows={[
                ['URI', <Copy text={d.spaceRecord.uri}>{shortUri(d.spaceRecord.uri)}</Copy>],
                ['Space', <Link to={spaceUrl(d.spaceRecord.space)}>{d.spaceRecord.space.replace(/^at:\/\/[^/]+\/space\//, '')}</Link>],
                ['State', d.spaceRecord.takendown ? <Chip k="err">hidden from space reads</Chip> : <Chip k="ok">served</Chip>],
              ]}
            />
            <div className="cx-form-row" style={{ marginTop: 8 }}>
              <SpaceRecordRead did={a.did} uri={d.spaceRecord.uri} />
              <ModButton s={s} applied={d.spaceRecord.takendown} handle={a.handle} caseId={caseId} label="record" />
            </div>
          </>
        )}
      </Sec>
    )
    const space = d.space && (
      <Sec title="Space" digest={d.space.takendown ? 'taken down' : d.space.exists ? 'live' : 'never created here'} open>
        <KV
          rows={[
            ['URI', <Copy text={d.space.uri}>{shortUri(d.space.uri)}</Copy>],
            ['State', <span className="cx-form-row" style={{ gap: 6 }}>{d.space.takendown ? <Chip k="err">taken down</Chip> : <Chip k="ok">live</Chip>}{!d.space.exists && <Chip k="idle">never created here</Chip>}{d.space.deleted && <Chip k="idle">deleted by its owner</Chip>}</span>],
          ]}
        />
        <div className="cx-form-row" style={{ marginTop: 8 }}>
          {d.space.exists && (
            <Link className="cx-btn sm" to={spaceUrl(d.space.uri)}>
              Space page
            </Link>
          )}
          <ModButton s={s} applied={d.space.takendown} handle={a.handle} caseId={caseId} label="space" />
        </div>
      </Sec>
    )
    const account = (
      <Sec title="Account" digest={`@${a.handle}${a.takedown.applied ? ' · taken down' : ''}`} open={s.kind === 'account' || page}>
        <KV
          rows={[
            ['DID', <Copy text={a.did} />],
            ['Status', <span className="cx-form-row" style={{ gap: 6 }}>{a.takedown.applied ? <Chip k="err">taken down</Chip> : <Chip k="ok">active</Chip>}{a.status && a.status !== 'takendown' && a.status !== 'active' && <span className="muted sm">{a.status}</span>}</span>],
            ...(a.takedown.ref ? [['Takedown ref', <span className="mono sm">{a.takedown.ref}</span>] as [string, ReactNode]] : []),
            ['Created', ago(ISO(a.createdAt))],
            ['Email', a.email ?? '—'],
          ]}
        />
        <div className="cx-form-row" style={{ marginTop: 8 }}>
          <button type="button" className="cx-btn sm" onClick={() => openAccount(a.did)}>
            Account
          </button>
          <ModButton s={{ kind: 'account', did: a.did }} applied={a.takedown.applied} handle={a.handle} caseId={caseId} label="account" />
        </div>
      </Sec>
    )
    const quota = (
      <Sec title="Blob quota" digest={d.quota.over ? 'over its quota' : `${fmtGB(d.quota.bytes)} stored`} open={d.quota.over || page} right={d.quota.over ? <Chip k="warn">over</Chip> : undefined}>
        {d.quota.over && (
          <p className="s-warn sm" style={{ margin: '0 0 8px' }}>
            Over its byte quota (a migration brought more than it allows). New uploads are refused until it’s under.
          </p>
        )}
        <KV rows={quotaRows(d.quota)} />
        <div style={{ marginTop: 8 }}>
          <button type="button" className="cx-btn sm" onClick={() => quotaDialog(a.did, d.quota)}>
            Change quota…
          </button>
        </div>
      </Sec>
    )
    const aboutCases = (
      <Sec title={s.kind === 'account' ? 'Cases about this account' : `Cases about this ${s.kind}`} digest={about.data ? plural(about.data.length, 'case') : '…'} open={!!about.data?.length} right={<Src>listCases · did, subject</Src>}>
        {about.data?.length ? (
          about.data.map((c) => (
            <RRow key={c.id} to={`/admin/moderation/cases/${encodeURIComponent(c.id)}`} x={<Chip k={CASE_TONE[c.status]}>{c.status}</Chip>}>
              <span className="mono sm">{c.id}</span>
              <span className="nm t2">{c.source}</span>
            </RRow>
          ))
        ) : (
          <div className="cx-empty">{about.error ? errText(about.error) : 'No case names it.'}</div>
        )}
      </Sec>
    )
    const history = (
      <Sec title="Audit log for this account" digest={audit.data ? `${plural(audit.data.length, 'entry', 'entries')}${audit.data.length >= 25 ? ' or more' : ''}` : ''} open={page} flush>
        {audit.data?.length ? (
          audit.data.map((e) => (
            <RRow key={e.id} onClick={() => openPanel('audit', e.id)} x={ago(ISO(e.at))}>
              <AuditAction a={e.action} />
              <span className="nm t2">{e.reason ?? (e.subject ? shortUri(auditSubjectText(e.subject)) : '')}</span>
            </RRow>
          ))
        ) : (
          <div className="cx-empty">{audit.error ? errText(audit.error) : 'Nothing yet.'}</div>
        )}
      </Sec>
    )
    // a spam report about an account wants what it's been posting
    const ops = s.kind === 'account' && <Ops did={a.did} mode={mode} open />
    const subjectCards = (
      <>
        {record}
        {blobs}
        {blob}
        {spaceRec}
        {space}
      </>
    )
    return {
      title,
      chip: applied ? <Chip k="err">taken down</Chip> : <Chip k="ok">{s.kind === 'account' ? 'active' : 'served'}</Chip>,
      foot: <Src>resolveSubject · getSubject · moderate</Src>,
      body: (
        <>
          <Strip
            items={[
              ['kind', s.kind],
              ['account', `@${a.handle}`],
              ['state', applied ? 'taken down' : 'visible'],
              ['blob storage', fmtGB(d.quota.bytes)],
            ]}
          />
          <CasePicker cases={cases.data} value={caseId} />
          {page ? (
            <div className="cols">
              <div>
                {subjectCards}
                {account}
                {ops}
              </div>
              <div>
                {quota}
                {aboutCases}
                {history}
              </div>
            </div>
          ) : (
            <>
              {subjectCards}
              {account}
              {ops}
              {quota}
              {aboutCases}
              {history}
            </>
          )}
        </>
      ),
    }
  },
})

// ---------------------------------------------------------------- case slide-over

function CaseSubject({ c, s }: { c: Case; s: SubjectRef }) {
  const v = useModVersion()
  const can = s.kind !== 'spaceRepo'
  const d = useLoad(() => (can ? getSubject(s) : Promise.resolve(undefined)), [subjectQuery(s), s.kind, v])
  const applied = appliedOf(d.data, s)
  const remove = useAction(() => updateCase(c.id, { removeSubject: s }))
  return (
    <div className="cxp-subj">
      <div className="cxp-subj-h">
        <Chip k="plain" glyph={false}>
          {s.kind}
        </Chip>
        <SubjectLabel s={s} handle={d.data?.account.handle} />
        {applied !== undefined && (applied ? <Chip k="err">taken down</Chip> : <Chip k="ok">visible</Chip>)}
      </div>
      <div className="cx-form-row">
        {can && (
          <button type="button" className="cx-btn sm" onClick={() => reviewSubject(s, c.id)}>
            Review
          </button>
        )}
        {can && applied !== undefined && <ModButton s={s} applied={applied} handle={d.data?.account.handle} caseId={c.id} label={s.kind} />}
        <button type="button" className="cx-btn sm quiet" disabled={remove.busy} onClick={() => remove.run()}>
          Remove from case
        </button>
        {!!(d.error || remove.error) && <span className="s-err sm">{errText(d.error || remove.error)}</span>}
      </div>
    </div>
  )
}

function AddSubject({ c }: { c: Case }) {
  const [q, setQ] = useState('')
  const add = useAction(async () => {
    const r = await resolveSubject(q.trim())
    await updateCase(c.id, { addSubject: { kind: r.kind, did: r.did, uri: r.uri, cid: r.cid } })
    setQ('')
  })
  return (
    <form
      className="cx-form-row"
      onSubmit={(e) => {
        e.preventDefault()
        if (q.trim()) add.run()
      }}
    >
      <input className="cx-inp mono" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Add a subject: URL, at:// URI, handle, DID + CID" aria-label="Add a subject" spellCheck={false} />
      <button className="cx-btn sm" disabled={add.busy || !q.trim()}>
        {add.busy && <Spinner />}
        Add
      </button>
      {!!add.error && <span className="s-err sm" style={{ flexBasis: '100%' }}>{errText(add.error)}</span>}
    </form>
  )
}

function CaseNotes({ c }: { c: Case }) {
  const [note, setNote] = useState('')
  const add = useAction(async () => {
    await updateCase(c.id, { note: note.trim() })
    setNote('')
  })
  return (
    <>
      {c.notes.length > 0 && (
        <ol className="cxp-notes">
          {c.notes.map((n, i) => (
            <li key={i}>
              <div className="muted sm">
                {ago(ISO(n.at))} · {n.actor}
                {n.auth && <span className="mono"> · {authShort(n.auth)}</span>}
                {n.ip && <span className="mono"> ({n.ip})</span>}
              </div>
              <div className="cxp-note">{n.text}</div>
            </li>
          ))}
        </ol>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (note.trim()) add.run()
        }}
      >
        <textarea className="cx-inp" rows={2} style={{ width: '100%', height: 'auto', padding: '8px 10px' }} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note (kept with the case): counter-notice received; restore window ends…" aria-label="Add a note" />
        <div className="cx-form-row" style={{ marginTop: 6, justifyContent: 'flex-end' }}>
          {!!add.error && <span className="s-err sm">{errText(add.error)}</span>}
          <button className="cx-btn sm" disabled={add.busy || !note.trim()}>
            {add.busy && <Spinner />}
            Add note
          </button>
        </div>
      </form>
    </>
  )
}

function CaseStatusSeg({ c }: { c: Case }) {
  const set = useAction(async (s: Case['status']) => {
    await updateCase(c.id, { status: s })
    toast(`Case marked ${s}`)
  })
  return (
    <div className="cx-form-row">
      <span className="t2 sm">Set status</span>
      <div className="cx-seg" role="group" aria-label="Case status">
        {CASE_STATUSES.map((s) => (
          <button key={s} type="button" className={c.status === s ? 'on' : undefined} aria-pressed={c.status === s} disabled={set.busy} onClick={() => c.status !== s && set.run(s)}>
            {c.status === s && <span className={`cx-g s-${CASE_TONE[s]}`}>{GLYPH[CASE_TONE[s]]}</span>}
            {s}
          </button>
        ))}
      </div>
      {!!set.error && <span className="s-err sm">{errText(set.error)}</span>}
    </div>
  )
}

registerDetail('case', {
  kind: 'Case',
  section: 'moderation',
  use: (id, mode) => {
    const v = useModVersion()
    const l = useLoad(() => getCase(id), [id, v])
    const c = l.data?.id === id ? l.data : undefined
    if (!c) return { title: <span className="mono">{id}</span>, body: null, loading: !l.error, missing: l.error ? errText(l.error) : undefined }
    const page = mode === 'page'
    const subjects = (
      <Sec title="Subjects" digest={c.subjects.length ? c.subjects.map((s) => s.kind).join(' + ') : 'none yet'} open>
        <div className="cx-stack" style={{ gap: 8 }}>
          {c.subjects.map((s) => (
            <CaseSubject key={`${s.kind}:${subjectQuery(s)}`} c={c} s={s} />
          ))}
          <AddSubject c={c} />
        </div>
      </Sec>
    )
    const notes = (
      <Sec title="Notes" digest={c.notes.length ? c.notes[c.notes.length - 1].text.slice(0, 60) : 'none yet'} open>
        <CaseNotes c={c} />
      </Sec>
    )
    const actions = (
      <Sec title="Takedowns and restores" digest={c.actions.length ? `${c.actions.length}` : 'none yet'} open={page || c.actions.length > 0} flush>
        {c.actions.length ? (
          c.actions.map((a) => (
            <RRow key={a.auditId} onClick={() => openPanel('audit', a.auditId)} x={ago(ISO(a.at))}>
              <Chip k={a.action === 'takedown' ? 'err' : 'ok'}>{a.action}</Chip>
              <span className="nm">
                <SubjectLabel s={a.subject} />
              </span>
            </RRow>
          ))
        ) : (
          <div className="cx-empty">Nothing taken down or restored under this case.</div>
        )}
      </Sec>
    )
    const details = (
      <Sec title="Details" digest={`opened ${ago(ISO(c.createdAt))}`} open={page}>
        <KV
          rows={[
            ['Id', <Copy text={c.id} />],
            ['Source', c.source],
            ['Opened', `${new Date(c.createdAt).toLocaleString()} (${ago(ISO(c.createdAt))})`],
            ['Updated', ago(ISO(c.updatedAt))],
          ]}
        />
      </Sec>
    )
    return {
      title: c.source,
      chip: <Chip k={CASE_TONE[c.status]}>{c.status}</Chip>,
      foot: <Src>getCase · updateCase · moderate</Src>,
      body: (
        <>
          <Strip
            items={[
              ['status', c.status],
              ['subjects', String(c.subjects.length)],
              ['notes', String(c.notes.length)],
              ['opened', ago(ISO(c.createdAt))],
            ]}
          />
          <CaseStatusSeg c={c} />
          {page ? (
            <div className="cols">
              <div>
                {subjects}
                {actions}
              </div>
              <div>
                {notes}
                {details}
              </div>
            </div>
          ) : (
            <>
              {subjects}
              {notes}
              {actions}
              {details}
            </>
          )}
        </>
      ),
    }
  },
})

// ---------------------------------------------------------------- audit entry slide-over

registerDetail('audit', {
  kind: 'Audit entry',
  section: 'moderation',
  use: (id) => {
    const seen = auditSeen.get(id)
    const l = useLoad<AuditEntry[]>(() => (seen ? Promise.resolve([seen]) : getAuditLog({ limit: 200 })), [id, !!seen])
    const e = seen ?? l.data?.find((x) => x.id === id)
    if (!e)
      return {
        title: <span className="mono">{id}</span>,
        body: null,
        loading: l.loading,
        missing: l.error ? errText(l.error) : 'Not among the newest 200 entries.',
      }
    const { label, tone } = auditAction(e.action)
    const s = e.subject
    const links = auditLinks(e)
    return {
      title: label,
      chip: tone ? <Chip k={tone}>{e.action}</Chip> : undefined,
      foot: <Src>getAuditLog</Src>,
      body: (
        <>
          <Sec title="Entry" digest={ago(ISO(e.at))} open>
            <KV
              rows={[
                ['When', `${new Date(e.at).toLocaleString()} (${ago(ISO(e.at))})`],
                ['Who', <>{e.actor}{e.ip && <span className="muted mono"> from {e.ip}</span>}</>],
                ['Signed in by', <span title="proxy: the login was verified by the proxy in front of the admin listener · token: the admin token, with the name the console sent">{authName(e.auth)}</span>],
                ['Node', <span className="mono">{e.node}</span>],
                ['Action', <span className="mono">{e.action}</span>],
                [
                  'Subject',
                  !s ? (
                    '—'
                  ) : isOperatorSubject(s) ? (
                    <OperatorSubjectLink s={s} />
                  ) : s.kind === 'spaceRepo' ? (
                    <SubjectLabel s={s} />
                  ) : (
                    <button type="button" className="cxp-link" onClick={() => reviewSubject(s)}>
                      <SubjectLabel s={s} />
                    </button>
                  ),
                ],
                ['Reason', e.reason ?? '—'],
                ['Case', e.caseId ? <button type="button" className="cxp-link mono" onClick={() => openPanel('case', e.caseId!)}>{e.caseId}</button> : '—'],
                ...links.map(([to, text]): [string, ReactNode] => ['See', <Link to={to}>{text}</Link>]),
                ['Id', <Copy text={e.id} />],
              ]}
            />
          </Sec>
          {e.detail != null && typeof e.detail === 'object' && Object.keys(e.detail as object).length > 0 && (
            <Sec title="Detail" open>
              <Json value={e.detail} />
            </Sec>
          )}
        </>
      ),
    }
  },
})

// ---------------------------------------------------------------- ⌘K

registerPalette({
  items: (q) => {
    const out = [
      { group: 'Actions', title: 'New moderation case…', desc: 'createCase', run: () => newCaseDialog(/^(at:\/\/|did:|https:\/\/bsky\.app\/)/.test(q) ? q : undefined) },
      ...(/^(did:\S+|@?[a-z0-9-]+(\.[a-z0-9-]+)+)$/i.test(q)
        ? [{ group: 'Actions', title: `Look up “${q.length > 40 ? `${q.slice(0, 40)}…` : q}” in Moderation`, desc: 'resolveSubject', run: () => navigate(`/admin/moderation?open=${encodeURIComponent(panelParam('subject', q.replace(/^@/, '')))}`) }]
        : []),
    ]
    const cases = (openCasesPoll.get().data ?? []).map((c) => ({
      group: 'Cases',
      glyph: '▲',
      title: c.source,
      desc: `open case · ${ago(ISO(c.createdAt))}`,
      hay: c.id,
      run: () => navigate(`/admin/moderation?open=${encodeURIComponent(panelParam('case', c.id))}`),
    }))
    return [...out, ...cases]
  },
})
