import { useEffect, useState, type ReactNode } from 'react'
import { confirmAction, FormDialog, openDialog } from '../../components/console/dialogs'
import { registerDetail } from '../../components/console/Drawer'
import { Chip, Copy, KV, Meter, Sec, Seg, Spark, Src, Strip } from '../../components/console/kit'
import { panelParam } from '../../components/console/nav'
import { registerPalette } from '../../components/console/Palette'
import { toast } from '../../components/console/toast'
import { ago, fmtNum, fmtSi } from '../../lib/console/fmt'
import {
  baseVersion,
  busiest,
  clearFactorLock,
  diffDrafts,
  draftOf,
  FACTOR_LABEL,
  fmtLimit,
  fmtWindow,
  freshLimits,
  held,
  KEY_LABEL,
  KEY_SHORT,
  lastActor,
  overrideTarget,
  rejectionHistory,
  rememberActor,
  rateLimitsQ,
  saveDraft,
  shortName,
  type Consumer,
  type Draft,
  type KeyKind,
  type Limiter,
  type OverrideCfg,
  type RateLimits,
  type RouteCfg,
  type SaveResult,
  isSignInBucket,
  splitIdentKey,
} from '../../lib/console/ratelimits'
import { listAccounts } from '../../lib/adminApi'
import { withAdmin } from '../../lib/console/adminAdapter'
import { lockoutsQ } from '../../lib/console/queries'
import { navigate } from '../../lib/router'
import { errText } from '../../lib/xrpc'
import { AccountLink } from './peopleUi'

// Limits & lockouts: the bucket and override slide-overs, the edit dialogs (every change is
// shown as a diff before updateRateLimits saves it), and ⌘K entries.

// ---------------------------------------------------------------- rows

/** One bucket as the console shows it: a built-in limiter or a per-method bucket from the config. */
export type BucketRow = {
  name: string
  key: KeyKind
  scope: string
  points: number
  windowSecs: number
  enabled: boolean
  /** A per-method bucket (config routes). */
  route?: RouteCfg
  def?: { points: number; windowSecs: number }
  /** Differs from its default. */
  changed: boolean
  m1: number
  m15: number
  top: Consumer[]
}

export function bucketRows(d: RateLimits): BucketRow[] {
  const rej = new Map<string, { m1: number; m15: number }>()
  for (const r of d.rejections) {
    const x = rej.get(r.limiter) ?? { m1: 0, m15: 0 }
    x.m1 += r.last1m
    x.m15 += r.last15m
    rej.set(r.limiter, x)
  }
  const routes = d.config?.routes ?? []
  const row = (l: Pick<Limiter, 'name' | 'key' | 'scope' | 'points' | 'windowSecs' | 'enabled'>, extra: Partial<BucketRow>): BucketRow => ({
    name: l.name,
    key: l.key,
    scope: l.scope,
    points: l.points,
    windowSecs: l.windowSecs,
    enabled: l.enabled,
    changed: false,
    m1: rej.get(l.name)?.m1 ?? 0,
    m15: rej.get(l.name)?.m15 ?? 0,
    top: d.top[l.name] ?? [],
    ...extra,
  })
  const out: BucketRow[] = []
  for (const l of d.limiters) {
    const route = l.name.startsWith('route:') ? routes.find((r) => `route:${r.nsid}` === l.name) : undefined
    const def = l.default ?? undefined
    out.push(row(l, { route, def, changed: route ? false : !!def && (l.points !== def.points || l.windowSecs !== def.windowSecs || !l.enabled) }))
  }
  for (const r of routes) {
    const name = `route:${r.nsid}`
    if (!out.some((x) => x.name === name)) out.push(row({ name, key: 'ip', scope: r.nsid, points: r.points, windowSecs: r.windowSecs, enabled: r.enabled !== false }, { route: r }))
  }
  return out
}

export const findBucket = (d: RateLimits | undefined, name: string) => (d ? bucketRows(d).find((b) => b.name === name) : undefined)

// ---------------------------------------------------------------- editing

function DiffList({ diff }: { diff: [string, string, string][] }) {
  return (
    <div className="cxp-diff">
      {diff.map(([what, a, b], i) => (
        <div key={i} className={!a ? 'add' : !b ? 'del' : undefined}>
          <span className="w">{what}</span>
          {a && <span className="a">{a}</span>}
          {a && b && <span className="muted">→</span>}
          {b && <span className="b">{b}</span>}
        </div>
      ))}
    </div>
  )
}

/**
 * Starts from the config the server has now, applies `mutate`, shows the diff and saves it
 * with ifVersion, so a save made elsewhere in between is refused instead of overwritten.
 */
export async function editLimits(o: { title: string; mutate: (x: Draft, d: RateLimits) => void; danger?: boolean; word?: string; what?: ReactNode }): Promise<boolean> {
  let d: RateLimits
  try {
    d = await freshLimits()
  } catch (e) {
    toast(errText(e), { err: true })
    return false
  }
  const before = draftOf(d)
  const after: Draft = structuredClone(before)
  o.mutate(after, d)
  const diff = diffDrafts(before, after)
  if (!diff.length) {
    toast('Nothing to change')
    return false
  }
  const base = baseVersion(d)
  return confirmAction({
    tone: o.danger ? 'err' : 'warn',
    title: o.title,
    items: [
      <DiffList diff={diff} />,
      ...(o.what ? [o.what] : []),
      `Saved as config v${base + 1}. Every node applies it within ${d.refreshSecs} s (the saving node nudges the others at once).`,
    ],
    fields: [
      { id: 'actor', label: 'Your name (kept in the change history)', initial: lastActor() },
      { id: 'note', label: 'Note (optional): why this change' },
    ],
    word: o.word,
    primary: !o.danger,
    action: `Save as v${base + 1}`,
    call: `vlpds.admin.updateRateLimits {ifVersion: ${base}}`,
    run: async (v) => {
      rememberActor(String(v.actor ?? ''))
      return saveDraft(d, after, String(v.actor ?? ''), String(v.note ?? ''))
    },
    done: (r) => {
      const s = r as SaveResult
      const ok = s.nodes.filter((n) => n.ok).length
      return `Saved v${s.version}: ${ok} of ${s.nodes.length} ${s.nodes.length === 1 ? 'node' : 'nodes'} running it`
    },
  })
}

export function toggleEnforcement(on: boolean) {
  return editLimits({
    title: on ? 'Turn rate limiting on?' : 'Turn rate limiting off?',
    danger: !on,
    word: on ? undefined : 'off',
    what: on ? 'Every bucket counts again from a fresh window.' : 'Nothing is counted or limited on any node, and the RateLimit headers go away.',
    mutate: (x) => void (x.enabled = on),
  })
}

export function clearLock(did: string, handle?: string | null, factor?: string) {
  return confirmAction({
    tone: 'warn',
    primary: true,
    title: `Clear the lockout for ${handle ? `@${handle}` : did}?`,
    items: [
      `Clears both factor locks (${FACTOR_LABEL.second_factor}, ${FACTOR_LABEL.email_code}) and their wrong-code counts${factor ? `; this one is on ${FACTOR_LABEL[factor] ?? factor}` : ''}.`,
      'Sign-in rate-limit buckets are separate: a DID override lifts those.',
    ],
    fields: [{ id: 'reason', label: 'Reason (audited as lockout.clear)', type: 'textarea', required: true }],
    word: handle ?? did,
    action: 'Clear lockout',
    call: 'vlpds.admin.clearLockout {did, reason}',
    run: async (v) => {
      await clearFactorLock(did, String(v.reason))
    },
    done: 'Lockout cleared',
  })
}

// ---------------------------------------------------------------- dialogs

/** Add an override; `prefill` from a held key ("exempt this IP from this bucket"). */
export function addOverrideDialog(prefill?: OverrideCfg) {
  openDialog((close) => <AddOverride close={close} prefill={prefill} />)
}

function AddOverride({ close, prefill }: { close: () => void; prefill?: OverrideCfg }) {
  const d = rateLimitsQ.get().data
  const names = d ? bucketRows(d).map((b) => b.name) : []
  const [kind, setKind] = useState<'ip' | 'did'>(prefill?.did ? 'did' : 'ip')
  const [who, setWho] = useState(prefill?.ip ?? prefill?.did ?? '')
  const [buckets, setBuckets] = useState((prefill?.limiters ?? []).join(', '))
  const [action, setAction] = useState<'exempt' | 'points'>(prefill?.points ? 'points' : 'exempt')
  const [points, setPoints] = useState(String(prefill?.points ?? 10000))
  const [note, setNote] = useState(prefill?.note ?? '')
  const list = buckets
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
  const unknown = names.length ? list.filter((b) => !names.includes(b)) : []
  const ok = !!who.trim() && !unknown.length && (action === 'exempt' || Number(points) > 0)
  const submit = () => {
    const o: OverrideCfg = kind === 'ip' ? { ip: who.trim() } : { did: who.trim() }
    if (list.length) o.limiters = list
    if (action === 'exempt') o.exempt = true
    else o.points = Math.floor(Number(points))
    if (note.trim()) o.note = note.trim()
    close()
    editLimits({ title: 'Add this override?', mutate: (x) => void x.overrides.push(o) })
  }
  return (
    <FormDialog title="Add an override" icon="+" call="reviewed as a diff, then vlpds.admin.updateRateLimits" action="Review…" disabled={!ok} onSubmit={submit} onCancel={close}>
      <div className="cx-form-row">
        <Seg label="Match on" value={kind} onChange={setKind} options={[{ v: 'ip', label: 'IP or CIDR' }, { v: 'did', label: 'DID' }]} />
        <input className="cx-inp mono" autoFocus value={who} onChange={(e) => setWho(e.target.value)} placeholder={kind === 'ip' ? '203.0.113.0/24' : 'did:plc:…'} aria-label={kind === 'ip' ? 'IP or CIDR block' : 'DID'} spellCheck={false} />
      </div>
      <div>
        <label className="cx-lbl" htmlFor="ov-b">
          Buckets (comma-separated; blank for all)
        </label>
        <input id="ov-b" className="cx-inp mono" list="cxp-bucket-names" value={buckets} onChange={(e) => setBuckets(e.target.value)} placeholder="all buckets" spellCheck={false} aria-invalid={unknown.length > 0 || undefined} />
        <datalist id="cxp-bucket-names">
          {names.map((n) => (
            <option key={n} value={n} />
          ))}
        </datalist>
        {unknown.length > 0 && <div className="s-err sm" style={{ marginTop: 4 }}>Unknown: {unknown.join(', ')}</div>}
      </div>
      <div className="cx-form-row">
        <Seg label="Action" value={action} onChange={setAction} options={[{ v: 'exempt', label: 'Exempt' }, { v: 'points', label: 'Custom limit' }]} />
        {action === 'points' && <input className="cx-inp mono" type="number" min={1} value={points} onChange={(e) => setPoints(e.target.value)} aria-label="Points" style={{ maxWidth: 140 }} />}
      </div>
      <div>
        <label className="cx-lbl" htmlFor="ov-n">
          Note
        </label>
        <input id="ov-n" className="cx-inp" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Relay, trusted service…" maxLength={280} />
      </div>
      <p className="muted sm" style={{ margin: 0 }}>
        An IP or CIDR override applies to every request from a matching client IP; a DID override to that account’s DID-keyed buckets. Exempt beats a custom limit; between custom limits the larger wins. It stays until you remove it.
      </p>
    </FormDialog>
  )
}

export function addRouteDialog() {
  openDialog((close) => <AddRoute close={close} />)
}

function AddRoute({ close }: { close: () => void }) {
  const d = rateLimitsQ.get().data
  const taken = (d?.config?.routes ?? []).map((r) => r.nsid)
  const [nsid, setNsid] = useState('')
  const [points, setPoints] = useState('300')
  const [win, setWin] = useState('300')
  const n = nsid.trim()
  const dup = taken.includes(n)
  const ok = /^[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+){2,}$/.test(n) && !dup && Number(points) > 0 && Number(win) > 0
  return (
    <FormDialog
      title="Add a per-method bucket"
      call="reviewed as a diff, then vlpds.admin.updateRateLimits"
      action="Review…"
      disabled={!ok}
      onCancel={close}
      onSubmit={() => {
        close()
        editLimits({ title: `Add a bucket for ${n}?`, mutate: (x) => void x.routes.push({ nsid: n, points: Math.floor(Number(points)), windowSecs: Math.floor(Number(win)), enabled: true }) })
      }}
    >
      <div>
        <label className="cx-lbl" htmlFor="rt-n">
          XRPC method
        </label>
        <input id="rt-n" className="cx-inp mono" autoFocus value={nsid} onChange={(e) => setNsid(e.target.value)} placeholder="app.bsky.feed.getTimeline" spellCheck={false} />
        {dup && <div className="s-err sm" style={{ marginTop: 4 }}>That method already has a bucket.</div>}
      </div>
      <LimitFields points={points} win={win} setPoints={setPoints} setWin={setWin} />
      <p className="muted sm" style={{ margin: 0 }}>
        Keyed by client IP and counted on top of global-ip.
      </p>
    </FormDialog>
  )
}

function LimitFields({ points, win, setPoints, setWin }: { points: string; win: string; setPoints: (v: string) => void; setWin: (v: string) => void }) {
  const w = Number(win)
  return (
    <div className="cx-form-row">
      <label className="cx-lbl" htmlFor="lf-p" style={{ margin: 0 }}>
        points
      </label>
      <input id="lf-p" className="cx-inp mono" type="number" min={1} value={points} onChange={(e) => setPoints(e.target.value)} style={{ maxWidth: 120 }} />
      <label className="cx-lbl" htmlFor="lf-w" style={{ margin: 0 }}>
        per window (s)
      </label>
      <input id="lf-w" className="cx-inp mono" type="number" min={1} max={604800} value={win} onChange={(e) => setWin(e.target.value)} style={{ maxWidth: 120 }} />
      <span className="muted sm">{w >= 60 && Number.isInteger(w) ? fmtWindow(w) : ''}</span>
    </div>
  )
}

/** The bucket slide-over's edit form. */
function ChangeLimit({ b }: { b: BucketRow }) {
  const [points, setPoints] = useState(String(b.points))
  const [win, setWin] = useState(String(b.windowSecs))
  const [on, setOn] = useState(b.enabled)
  const p = Math.floor(Number(points))
  const w = Math.floor(Number(win))
  const valid = p > 0 && w > 0 && w <= 604800
  const dirty = p !== b.points || w !== b.windowSecs || on !== b.enabled
  const apply = (x: Draft) => {
    if (b.route) {
      const r = x.routes.find((r) => r.nsid === b.route!.nsid)
      if (r) Object.assign(r, { points: p, windowSecs: w, enabled: on })
    } else if (x.limiters[b.name]) x.limiters[b.name] = { points: p, windowSecs: w, enabled: on }
  }
  return (
    <>
      <LimitFields points={points} win={win} setPoints={setPoints} setWin={setWin} />
      <div className="cx-form-row" style={{ marginTop: 8 }}>
        <Seg label="Bucket on or off" value={on ? 'on' : 'off'} onChange={(v) => setOn(v === 'on')} options={[{ v: 'on', label: 'on' }, { v: 'off', label: 'off' }]} />
        <button type="button" className="cx-btn sm primary" disabled={!valid || !dirty} onClick={() => editLimits({ title: `Change ${shortName(b.name)}?`, mutate: apply, danger: !on && b.enabled })}>
          Review and save…
        </button>
        {b.def && b.changed && (
          <button
            type="button"
            className="cx-btn sm quiet"
            onClick={() => editLimits({ title: `Reset ${shortName(b.name)} to its default?`, mutate: (x) => void (x.limiters[b.name] = { ...b.def!, enabled: true }) })}
          >
            Reset to default ({fmtLimit(b.def.points, b.def.windowSecs)})
          </button>
        )}
      </div>
      <p className="muted sm" style={{ margin: '8px 0 0' }}>
        A new points value keeps each key’s live window. A new window length starts every key fresh.
      </p>
    </>
  )
}

export function overrideFor(b: { name: string; key: KeyKind }, key: string): OverrideCfg | undefined {
  const t = overrideTarget(b.key, key)
  return t && { ...t, limiters: [b.name], exempt: true }
}

/**
 * A key's use: what the busiest node counted, then a fixed-width meter, for a right-aligned
 * cell so counts and meters line up down a column. `of`: the bucket's limit, already shown
 * in its own column, so only a key whose override changes it repeats it.
 */
export function KeyUse({ c, of }: { c: Consumer; of?: number }) {
  if (c.limit == null)
    return (
      <span className="cxp-use" title={`exempt by an override; ${fmtNum(c.used)} counted`}>
        <span className="n">{fmtNum(c.used)}</span>
        <Chip k="info" glyph={false}>
          exempt
        </Chip>
      </span>
    )
  const f = c.maxNodeUsed / c.limit
  return (
    <span className="cxp-use" title={`${fmtNum(c.used)} used cluster-wide; ${fmtNum(c.maxNodeUsed)} of ${fmtNum(c.limit)} on the busiest node`}>
      <span className="n">
        {fmtNum(c.maxNodeUsed)}
        {c.limit !== of && <span className="muted">/{fmtNum(c.limit)}</span>}
      </span>
      <Meter v={Math.min(c.maxNodeUsed, c.limit)} max={c.limit} k={f >= 1 ? 'err' : f >= 0.8 ? 'warn' : undefined} />
    </span>
  )
}

const identDid = new Map<string, Promise<string | null>>()

/** The account an identifier (handle or email) names on this PDS, looked up once per tab. */
function didOfIdent(ident: string): Promise<string | null> {
  let p = identDid.get(ident)
  if (!p) {
    p = withAdmin((c) => listAccounts(c, { q: ident, limit: 5 }))
      .then((r) => r.accounts.find((a) => a.handle.toLowerCase() === ident || a.email?.toLowerCase() === ident || a.did === ident)?.did ?? null)
      .catch(() => null)
    identDid.set(ident, p)
  }
  return p
}

/** A sign-in key as the account it holds back when the key names one: a DID key, or an identifier + IP key whose identifier is a handle or email here. */
export function KeyWho({ kind, k, w }: { kind: KeyKind; k: string; w?: number }) {
  const ident = kind === 'identifier-ip' ? splitIdentKey(k) : undefined
  const [did, setDid] = useState<string | null | undefined>(kind === 'did' && k.startsWith('did:') ? k : undefined)
  useEffect(() => {
    if (ident) didOfIdent(ident.ident).then(setDid)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [k])
  if (!did) return <KeyId k={k} w={w} />
  return (
    <span title={`${k}\nOpens the account`}>
      <AccountLink did={did} handle={ident && !ident.ident.includes('@') && !ident.ident.startsWith('did:') ? ident.ident : undefined} />
    </span>
  )
}

/** A key truncated to a fixed width; the whole key on hover, copied on click. */
export const KeyId = ({ k, w }: { k: string; w?: number }) => (
  <Copy text={k} full className="cxp-key">
    <span style={w ? { width: w } : undefined}>{k}</span>
  </Copy>
)

// ---------------------------------------------------------------- slide-overs

registerDetail('bucket', {
  kind: 'Rate-limit bucket',
  section: 'limits',
  use: (id, mode) => {
    const s = rateLimitsQ.use()
    const d = s.data
    const b = findBucket(d, id)
    if (!d) return { title: <span className="mono">{id}</span>, body: null, loading: !s.error, missing: s.error ? errText(s.error) : undefined }
    if (!b) return { title: <span className="mono">{id}</span>, body: null, missing: `No bucket named ${id} on this server.` }
    const hist = rejectionHistory()
    const h = hist.byBucket.get(b.name) ?? hist.total.map(() => 0)
    const routesHere = d.rejections.filter((r) => r.limiter === b.name && r.total > 0)
    const top = [...b.top].sort((x, y) => y.maxNodeUsed - x.maxNodeUsed)
    const page = mode === 'page'
    return {
      title: <span className="mono">{shortName(b.name)}</span>,
      chip: !b.enabled ? <Chip k="idle">off</Chip> : b.m1 ? <Chip k="warn">{b.m1} 429s/min</Chip> : <Chip k="ok">quiet</Chip>,
      updated: s.at,
      foot: <Src>getRateLimits · updateRateLimits</Src>,
      body: (
        <>
          <Strip
            items={[
              ['limit', fmtNum(b.points)],
              ['window', fmtWindow(b.windowSecs)],
              ['429s, 1 min', fmtNum(b.m1)],
              ['429s, 15 min', fmtNum(b.m15)],
              ['keys counted', fmtNum(b.top.length)],
            ]}
          />
          <Sec title="429s per second" digest={h.length > 1 ? `since this console opened, peak ${fmtSi(Math.max(...h))}/s` : 'collecting samples'} open>
            <Spark data={h} color="warn" size="big" min={0.05} />
          </Sec>
          <Sec title="Top keys" digest={`current ${fmtWindow(b.windowSecs)} window, by ${KEY_LABEL[b.key]}`} open flush>
            {top.length ? (
              <div className="cx-tw">
                <table className="cx-t compact">
                  <thead>
                    <tr>
                      <th>Key</th>
                      <th className="r" title="What the busiest node counted against the limit">
                        Used of {fmtNum(b.points)}
                      </th>
                      <th className="r">Resets</th>
                      <th>
                        <span className="sr">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {top.map((c) => {
                      const ov = overrideFor(b, c.key)
                      return (
                        <tr key={c.key}>
                          <td style={{ width: '100%' }}>
                            {held(c) && isSignInBucket(b) ? <KeyWho kind={b.key} k={c.key} w={200} /> : <KeyId k={c.key} w={200} />}
                            {c.nodes.length > 1 && <span className="muted sm"> ×{c.nodes.length}</span>}
                          </td>
                          <td className="r">
                            <KeyUse c={c} of={b.points} />
                          </td>
                          <td className="r muted">{ago(c.resetMs)}</td>
                          <td className="r">
                            {ov && c.limit != null && (
                              <button type="button" className="cx-btn sm quiet" onClick={() => addOverrideDialog(ov)}>
                                Exempt…
                              </button>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="cx-empty">Nothing counted in this bucket right now.</div>
            )}
          </Sec>
          {(b.def || b.route) && (
            <Sec title="Change limit" digest={b.changed ? `changed from ${fmtLimit(b.def!.points, b.def!.windowSecs)}` : b.route ? 'added bucket' : 'default'} open>
              <ChangeLimit key={`${b.name}:${b.points}:${b.windowSecs}:${b.enabled}`} b={b} />
            </Sec>
          )}
          {routesHere.length > 0 && (
            <Sec title="429s by route" digest={`${routesHere.length}`} open={page} flush>
              <div className="cx-tw">
                <table className="cx-t compact">
                  <thead>
                    <tr>
                      <th>Route</th>
                      <th className="r">1m</th>
                      <th className="r">5m</th>
                      <th className="r">15m</th>
                      <th className="r">Since start</th>
                    </tr>
                  </thead>
                  <tbody>
                    {routesHere.map((r) => (
                      <tr key={r.route}>
                        <td className="mono sm">{r.route}</td>
                        <td className="r">{fmtNum(r.last1m)}</td>
                        <td className="r">{fmtNum(r.last5m)}</td>
                        <td className="r">{fmtNum(r.last15m)}</td>
                        <td className="r">{fmtNum(r.total)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Sec>
          )}
          <Sec title="About" digest={KEY_SHORT[b.key]} open={page}>
            <KV
              rows={[
                ['Name', <Copy text={b.name} />],
                ['Keyed by', KEY_LABEL[b.key]],
                ['Covers', b.scope],
                ['Default', b.def ? fmtLimit(b.def.points, b.def.windowSecs) : 'none (added in the config)'],
                ['Counted', b.key === 'cluster' ? 'once, in the bucket; windows aligned to the epoch' : 'on each node separately'],
              ]}
            />
            {b.route && (
              <div style={{ marginTop: 10 }}>
                <button type="button" className="cx-btn sm danger" onClick={() => editLimits({ title: `Remove the ${b.route!.nsid} bucket?`, danger: true, mutate: (x) => void (x.routes = x.routes.filter((r) => r.nsid !== b.route!.nsid)) })}>
                  Remove bucket…
                </button>
              </div>
            )}
          </Sec>
        </>
      ),
    }
  },
})

const sameOverride = (a: OverrideCfg, b: OverrideCfg) => JSON.stringify(a) === JSON.stringify(b)

registerDetail('override', {
  kind: 'Rate-limit override',
  section: 'limits',
  use: (id) => {
    const s = rateLimitsQ.use()
    const o = s.data?.config?.overrides?.[Number(id)]
    if (!s.data) return { title: id, body: null, loading: !s.error, missing: s.error ? errText(s.error) : undefined }
    if (!o) return { title: id, body: null, missing: 'This override is gone: it was removed or the list changed. Reopen it from the Overrides table.' }
    return {
      title: <span className="mono">{o.ip ?? o.did}</span>,
      chip: <Chip k="info">{o.ip ? 'IP' : 'DID'}</Chip>,
      updated: s.at,
      foot: <Src>getRateLimits · updateRateLimits</Src>,
      body: (
        <>
          <Sec title="Override" digest={o.exempt ? 'exempt' : `${fmtNum(o.points)} points`} open>
            <KV
              rows={[
                ['Match', <Copy text={o.ip ?? o.did ?? ''} />],
                ['Buckets', o.limiters?.length ? <span className="mono sm">{o.limiters.map(shortName).join(', ')}</span> : 'all'],
                ['Action', o.exempt ? 'exempt from the limit' : `a limit of ${fmtNum(o.points)} points per window`],
                ['Note', o.note ?? '—'],
              ]}
            />
          </Sec>
          <div>
            <button type="button" className="cx-btn sm danger" onClick={() => editLimits({ title: 'Remove this override?', danger: true, mutate: (x) => void (x.overrides = x.overrides.filter((y) => !sameOverride(y, o))) })}>
              Remove override…
            </button>
          </div>
        </>
      ),
    }
  },
})

// ---------------------------------------------------------------- ⌘K

registerPalette({
  items: () => {
    const d = rateLimitsQ.get().data
    const locks = lockoutsQ.get().data
    const out: { group: string; title: string; desc?: string; glyph?: ReactNode; hay?: string; run: () => void }[] = [
      {
        group: 'Actions',
        title: 'Add rate-limit override…',
        desc: 'updateRateLimits',
        run: () => {
          navigate('/admin/limits')
          addOverrideDialog()
        },
      },
    ]
    if (d)
      out.push({
        group: 'Actions',
        title: d.config?.enabled === false ? 'Turn rate limiting on…' : 'Turn rate limiting off…',
        desc: `config v${d.configVersion}`,
        run: () => toggleEnforcement(d.config?.enabled === false),
      })
    if (locks?.supported)
      for (const l of locks.data)
        out.push({ group: 'Actions', title: `Clear lockout for ${l.handle ? `@${l.handle}` : l.did}…`, desc: FACTOR_LABEL[l.factor] ?? l.factor, hay: l.did, run: () => clearLock(l.did, l.handle, l.factor) })
    for (const b of d ? bucketRows(d) : [])
      out.push({
        group: 'Rate limits',
        glyph: b.m1 ? '▲' : '›',
        title: shortName(b.name),
        desc: `${fmtLimit(b.points, b.windowSecs)} · ${KEY_SHORT[b.key]}${busiest(b.top) && held(busiest(b.top)!) ? ' · a key is held' : ''}`,
        hay: b.scope,
        run: () => navigate(`/admin/limits?open=${encodeURIComponent(panelParam('bucket', b.name))}`),
      })
    return out
  },
})
