import { useState, type ReactNode } from 'react'
import { registerDetail, type DetailMode } from '../../components/console/Drawer'
import { Banners, Chip, Copy, ErrorState, Json, KV, Loading, Meter, NeedsVersion, RRow, Sec, Spinner, Src, Strip, type BannerSpec, type ChipKind, type KVRow } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import { registerPalette, type PalItem } from '../../components/console/Palette'
import { toast } from '../../components/console/toast'
import * as api from '../../lib/adminApi'
import type { AccountRow, AccountSecurity, MailEntry, RepoOpsResult, Session, SignInFailure } from '../../lib/adminApi'
import { withAdmin } from '../../lib/console/adminAdapter'
import { useClusterView } from '../../lib/console/cluster'
import { ago, authName, dur, factorName, fmtBytes, fmtNum, plural, shortDid } from '../../lib/console/fmt'
import { isUnsupported } from '../../lib/console/live'
import { heldSignInKeys, rlPoll, shortName, type HeldKey } from '../../lib/console/ratelimits'
import { useLoad } from '../../lib/hooks'
import { Link } from '../../lib/router'
import { admin, call, errText } from '../../lib/xrpc'
import * as act from './accountActions'
import { useAccountsVersion, type Quota, type Who } from './accountActions'
import { accountState, TwoFactor } from './Accounts'
import { AuditAction } from './auditUi'
import { NodeTag } from './clusterUi'
import { addOverrideDialog, overrideFor } from './limitsUi'
import { MailChip, mailId, mailOutcome, mailTone, purposeLabel } from './Mail'

// The account detail, in the slide-over or as a full page: identity, placement, sign-in and
// second factors, sessions, recent ops, blobs and quota, invites, spaces, moderation, and the
// actions (accountActions.tsx). The row comes from listAccounts (an exact DID is one lookup on
// the owner); the rest loads per section.

type InviteCode = { code: string; available: number; disabled: boolean; forAccount: string; createdBy: string; createdAt: string; uses: { usedBy: string; usedAt: string }[] }
type AccountInfo = {
  did: string
  handle: string
  email?: string
  indexedAt: string
  emailConfirmedAt?: string
  deactivatedAt?: string
  deletionScheduledAt?: string
  invitesDisabled?: boolean
  invites?: InviteCode[]
  invitedBy?: InviteCode
}
type SubjectStatus = { takedown?: { applied: boolean; ref?: string }; deactivated?: { applied: boolean } }
type SubjectDetail = { quota: Quota }

const when = (ms?: number | null) => (ms ? ago(ms) : '—')
const iso = (s?: string | null) => (s ? ago(new Date(s).getTime()) : '—')
const date = (s?: string | number | null) => (s ? new Date(s).toISOString().slice(0, 10) : '—')

/** Opens another detail from inside this one. */
function Open({ type, id, children }: { type: string; id: string; children: ReactNode }) {
  return (
    <button type="button" className="cx-linklike" onClick={() => openPanel(type, id)}>
      {children}
    </button>
  )
}

function Act({ t, d, children }: { t: string; d: string; children: ReactNode }) {
  return (
    <div className="cx-act">
      <div className="ad">
        <b>{t}</b>
        {d}
      </div>
      {children}
    </div>
  )
}

const btn = (label: string, run: () => unknown, danger?: boolean) => (
  <button type="button" className={`cx-btn sm${danger ? ' danger' : ''}`} onClick={run}>
    {label}
  </button>
)

// ---------------------------------------------------------------- can they sign in?

type Load<T> = ReturnType<typeof useLoad<T>>

const FAILED: Record<SignInFailure, string> = { wrong_password: 'wrong password', wrong_code: 'wrong code', factor_locked: 'code locked', rate_limited: 'rate-limited' }
const FAILED_TEXT: Record<SignInFailure, string> = {
  wrong_password: 'Refused: the password (or app password) was wrong',
  wrong_code: 'Refused: a wrong second-factor code, recovery code or passkey',
  factor_locked: 'Refused: the second factor was locked after wrong codes',
  rate_limited: 'Refused: a sign-in rate limit held it (Limits & lockouts)',
}

/** One line under the banners: everything that decides whether a sign-in works, in the order it's checked. */
function CanSignIn({ a, k, t, i, sec, held, mail }: { a: Who; k: ChipKind; t: string; i?: AccountInfo; sec: Load<AccountSecurity>; held: HeldKey[]; mail?: MailEntry }) {
  const s = sec.data
  const now = Date.now()
  const factors = s ? [s.totp.enabled && 'authenticator', s.passkeys.length && plural(s.passkeys.length, 'passkey'), s.emailCode.enabled && 'email code'].filter(Boolean) : []
  const locks = (s?.lockouts ?? []).filter((l) => l.lockedUntil && l.lockedUntil > now)
  const good = s?.recentSignIns.find((x) => !x.failed)
  const day = (s?.recentSignIns ?? []).filter((x) => x.failed && now - x.at < 86_400_000)
  const refused = day.reduce((n, x) => n + (x.count ?? 1), 0)
  return (
    <div className="cx-cansign" aria-label="Can they sign in?">
      <div className="cx-eyebrow">Can they sign in?</div>
      <div className="cx-acc-chips">
        <Chip k={k}>{t}</Chip>
        {!s ? (
          sec.error ? <Chip k="idle">sign-in details unavailable</Chip> : <Chip k="idle">…</Chip>
        ) : (
          <>
            {s.oauthOnly ? <Chip k="info">OAuth only</Chip> : s.passwordSet ? <Chip k="ok">password set</Chip> : <Chip k="warn">no password</Chip>}
            {factors.length ? <Chip k="ok">{factors.join(' · ')}</Chip> : <Chip k="idle">no second factor</Chip>}
            {locks.length ? (
              <>
                <Chip k="err">
                  {locks.map((l) => factorName(l.factor)).join(' and ')} locked · clears in {dur(Math.max(...locks.map((l) => l.lockedUntil!)) - now)}
                </Chip>
                {btn('Unlock…', () => act.clearLockout(a))}
              </>
            ) : (
              <Chip k="ok">no factor locks</Chip>
            )}
          </>
        )}
        {held.map((h) => {
          const ov = overrideFor(h.bucket, h.c.key)
          return (
            <span key={`${h.bucket.name}/${h.c.key}`} className="cx-acc-chips">
              <Chip k="err" title={`${h.c.key}: ${h.c.maxNodeUsed} of ${h.c.limit} on the busiest node`}>
                sign-in held · {shortName(h.bucket.name)} · {fmtNum(h.c.maxNodeUsed)}/{fmtNum(h.c.limit ?? 0)} · clears in {dur(h.c.resetMs - now)}
              </Chip>
              {ov ? btn('Exempt…', () => addOverrideDialog({ ...ov, note: `@${a.handle}, lifted ${new Date().toISOString().slice(0, 10)}` })) : null}
            </span>
          )
        })}
      </div>
      <div className="cx-acc-chips">
        {s &&
          (good ? (
            <Chip k="plain" title={good.userAgent ?? undefined}>
              last good sign-in {ago(good.at)} · {good.device}
            </Chip>
          ) : (
            <Chip k="idle">no sign-in in 30 days</Chip>
          ))}
        {refused > 0 && (
          <Chip k="warn" title="Refused sign-ins in the last 24 hours (Recent sign-ins)">
            {plural(refused, 'refused attempt')} in 24 h · {[...new Set(day.map((x) => FAILED[x.failed!]))].join(', ')}
          </Chip>
        )}
        {i && (i.email ? i.emailConfirmedAt ? <Chip k="ok">email confirmed</Chip> : <Chip k="warn">email unconfirmed</Chip> : <Chip k="idle">no email</Chip>)}
        {mail && (
          <Chip k={mailTone(mail)} title={`${mail.purpose} to …@${mail.toDomain}, ${new Date(mail.at).toLocaleString()}`}>
            {purposeLabel(mail.purpose)} sent {ago(mail.at)} · {mailOutcome(mail)}
          </Chip>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- sections

function Security({ a, sec }: { a: Who; sec: ReturnType<typeof useLoad<AccountSecurity>> }) {
  const s = sec.data
  const factors = s ? [s.passkeys.length ? plural(s.passkeys.length, 'passkey') : '', s.totp.enabled ? 'authenticator app' : '', s.emailCode.enabled ? 'email code' : ''].filter(Boolean) : []
  return (
    <Sec title="Sign-in & two-factor" digest={!s ? '…' : factors.length ? factors.join(' · ') : s.oauthOnly ? 'OAuth only' : 'password only'} open right={<Src>getAccountSecurity</Src>}>
      {sec.error ? (
        isUnsupported(sec.error) ? <NeedsVersion what="Sign-in details" nsid="vlpds.admin.getAccountSecurity" /> : <ErrorState error={sec.error} retry={sec.reload} />
      ) : !s ? (
        <Loading />
      ) : (
        <KV
          rows={[
            [
              'Password',
              s.oauthOnly ? <span className="t2">no password sign-in</span> : s.passwordSet ? 'set' : <span className="muted">not set</span>,
              { chip: s.oauthOnly ? <Chip k="info">OAuth only</Chip> : undefined, act: !s.oauthOnly && btn('Set password…', () => act.setPassword(a)) },
            ],
            [
              'Second factor',
              s.secondFactorRequired ? 'asked at every password sign-in' : <span className="muted">not asked</span>,
              { chip: onOff(s.secondFactorRequired, 'required'), act: btn('Reset two-factor…', () => act.resetSecondFactors(a), true) },
            ],
            [
              'Passkeys',
              s.passkeys.length ? (
                <span className="cx-acc-chips">
                  {s.passkeys.map((p) => (
                    <Chip key={p.name + p.createdAt} k={p.suspect ? 'warn' : 'plain'} title={`added ${date(p.createdAt)}${p.lastUsedAt ? `, used ${ago(p.lastUsedAt)}` : ''}${p.backedUp ? ', synced' : ''}`}>
                      {p.name}
                      {p.suspect ? ' · copied?' : ''}
                    </Chip>
                  ))}
                </span>
              ) : (
                <span className="muted">none</span>
              ),
              { chip: onOff(s.passkeys.length > 0) },
            ],
            ['Authenticator app', s.totp.enabled ? (s.totp.enabledAt ? `since ${date(s.totp.enabledAt)}` : 'set up') : <span className="muted">not set up</span>, { chip: onOff(s.totp.enabled) }],
            ['Email code', s.emailCode.enabled ? (s.emailCode.since ? `since ${date(s.emailCode.since)}` : 'set up') : <span className="muted">not set up</span>, { chip: onOff(s.emailCode.enabled) }],
            [
              'Recovery codes',
              s.recoveryCodes.issuedAt ? `${s.recoveryCodes.remaining} of ${s.recoveryCodes.total} left` : <span className="muted">none issued</span>,
              { chip: s.recoveryCodes.issuedAt && s.recoveryCodes.remaining <= 2 ? <Chip k="warn">low</Chip> : undefined },
            ],
            ['Trusted browsers', fmtNum(s.trustedBrowsers.length)],
            ['App passwords', s.blockAppPasswords ? <span className="t2">refused at sign-in</span> : fmtNum(s.appPasswords.length), { chip: s.blockAppPasswords ? <Chip k="info">blocked by the owner</Chip> : undefined }],
            ...s.lockouts
              .filter((l) => l.failures > 0 || l.lockedUntil)
              .map((l): KVRow => {
                const locked = !!l.lockedUntil && l.lockedUntil > Date.now()
                return [factorName(l.factor), plural(l.failures, 'wrong code'), { chip: locked ? <Chip k="err">locked</Chip> : undefined, act: locked ? btn('Unlock…', () => act.clearLockout(a)) : undefined }]
              }),
          ]}
        />
      )}
    </Sec>
  )
}

const onOff = (on: boolean, label = 'on') => (on ? <Chip k="ok">{label}</Chip> : <Chip k="idle">off</Chip>)

const METHOD: Record<string, string> = { password: 'password', app_password: 'app password', oauth: 'OAuth', passkey: 'passkey' }
const FACTOR: Record<string, string> = { totp: 'authenticator', email: 'email code', passkey: 'passkey', recovery: 'recovery code', trusted: 'trusted browser' }

/** An OAuth client by its host ("boards.example.com"); the id itself when it isn't a URL. */
export function clientHost(id: string): string {
  try {
    return new URL(id).hostname || id
  } catch {
    return id
  }
}

/** A client id as its host, the full id on hover. */
const Client = ({ id }: { id: string }) => (
  <span className="trunc cx-acc-cell" title={id}>
    {clientHost(id)}
  </span>
)

/** The parsed device ("Chrome on macOS"), the user agent it came from on hover. */
const Device = ({ name, ua }: { name?: string | null; ua?: string | null }) => (
  <span className="trunc cx-acc-cell" title={ua ?? undefined}>
    {name ?? '—'}
  </span>
)

function SignIns({ sec, mode }: { sec: ReturnType<typeof useLoad<AccountSecurity>>; mode: DetailMode }) {
  const [more, setMore] = useState(false)
  const s = sec.data
  if (!s?.recentSignIns.length) return null
  const all = s.recentSignIns
  const n = more ? all.length : mode === 'page' ? 15 : 10
  const fresh = all.filter((x) => x.newDevice).length
  const good = all.filter((x) => !x.failed)
  const bad = all.length - good.length
  const digest = [`${good.length} in 30 days`, good.length ? `last ${ago(good[0].at)}` : '', bad ? `${fmtNum(bad)} refused` : '', fresh ? `${fresh} from a new device` : ''].filter(Boolean).join(' · ')
  return (
    <Sec title="Recent sign-ins" digest={digest} open flush right={<Src>getAccountSecurity</Src>}>
      <div className="cx-tw">
        <table className="cx-t compact cx-acc-signins">
          <thead>
            <tr>
              <th>When</th>
              <th>Method</th>
              <th>Client</th>
              <th>Device</th>
              <th>IP</th>
              <th>
                <span className="sr">New device</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {all.slice(0, n).map((x, i) => (
              <tr key={i} className={x.failed ? 'cx-refused' : undefined}>
                <td title={x.firstAt && x.firstAt !== x.at ? `${new Date(x.firstAt).toLocaleString()} to ${new Date(x.at).toLocaleString()}` : new Date(x.at).toLocaleString()}>{ago(x.at)}</td>
                <td>
                  {METHOD[x.method] ?? x.method}
                  {x.factor && x.factor !== x.method && <span className="muted"> + {FACTOR[x.factor] ?? x.factor}</span>}
                </td>
                <td>{x.clientId ? <Client id={x.clientId} /> : x.method === 'app_password' && x.appPassword ? <span className="trunc cx-acc-cell">“{x.appPassword}”</span> : <span className="muted">—</span>}</td>
                <td>
                  <Device name={x.device} ua={x.userAgent} />
                </td>
                <td className="mono sm">{x.ip ?? '—'}</td>
                <td style={{ width: '100%' }}>
                  {x.failed ? (
                    <Chip k={x.failed === 'wrong_password' || x.failed === 'wrong_code' ? 'warn' : 'err'} title={FAILED_TEXT[x.failed]}>
                      {FAILED[x.failed]}
                      {(x.count ?? 1) > 1 ? ` ×${x.count}` : ''}
                    </Chip>
                  ) : (
                    x.newDevice && <Chip k="info">new device</Chip>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {all.length > (mode === 'page' ? 15 : 10) && (
        <div className="cx-pn-f">
          <span>{more ? `All ${all.length}, newest first (the server keeps 30 days: at most 50 sign-ins and 20 refused).` : `The ${n} newest of ${all.length}.`}</span>
          <button type="button" className="cx-linklike" style={{ marginLeft: 'auto' }} onClick={() => setMore((v) => !v)}>
            {more ? 'Show fewer' : `Show all ${all.length}`}
          </button>
        </div>
      )}
    </Sec>
  )
}

function sessionLabel(s: Session): string {
  if (s.kind === 'oauth') return s.clientId
  if (s.kind === 'appPassword') return `app password “${s.appPassword ?? ''}”`
  return 'password session'
}

function Sessions({ a, l, mode }: { a: Who; l: Load<{ did: string; sessions: Session[] }>; mode: DetailMode }) {
  const [more, setMore] = useState(false)
  const ss = l.data?.sessions ?? []
  const oauth = ss.filter((s) => s.kind === 'oauth').length
  const first = mode === 'page' ? 15 : 10
  return (
    <Sec title="Sessions" digest={l.data ? `${ss.length} signed in · ${oauth} OAuth` : '…'} open flush right={<Src>listSessions</Src>}>
      {l.error ? (
        isUnsupported(l.error) ? <NeedsVersion what="Sessions" nsid="vlpds.admin.listSessions" /> : <ErrorState error={l.error} retry={l.reload} />
      ) : !l.data ? (
        <Loading />
      ) : !ss.length ? (
        <div className="cx-empty">No live sessions.</div>
      ) : (
        <>
          <div className="cx-tw">
            <table className="cx-t compact">
              <thead>
                <tr>
                  <th>App</th>
                  <th>Device</th>
                  <th>IP</th>
                  <th className="r">Signed in</th>
                  <th className="r">Last refresh</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {ss.slice(0, more ? 200 : first).map((s) => (
                  <tr key={s.id} title={s.kind === 'oauth' ? s.scope : undefined}>
                    <td>
                      <span className="cx-cellid">
                        {s.kind === 'oauth' ? <Client id={s.clientId} /> : s.kind === 'appPassword' ? <span className="trunc cx-acc-cell">app password “{s.appPassword ?? ''}”</span> : 'password'}
                        {s.kind !== 'oauth' && s.privileged && <Chip k="warn">privileged</Chip>}
                        {s.passkey && <Chip k="acc">passkey</Chip>}
                      </span>
                    </td>
                    <td>{s.kind === 'oauth' ? <Device name={s.device} ua={s.userAgent} /> : <span className="muted">—</span>}</td>
                    <td className="mono sm" style={{ width: '100%' }} title={s.signedInIp ? `signed in from ${s.signedInIp}` : undefined}>
                      {s.ip ?? '—'}
                    </td>
                    <td className="r">{when(s.signedInAt)}</td>
                    <td className="r">{when(s.refreshedAt)}</td>
                    <td className="r">
                      <button type="button" className="cx-btn sm quiet" onClick={() => act.revokeSession(a, s.id, sessionLabel(s))}>
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="cx-pn-f">
            {btn('Sign out everywhere…', () => act.signOutEverywhere(a, ss.length), true)}
            {ss.length > first && (
              <button type="button" className="cx-linklike" style={{ marginLeft: 'auto' }} onClick={() => setMore((x) => !x)}>
                {more ? 'Show fewer' : `Show all ${ss.length}`}
              </button>
            )}
          </div>
        </>
      )}
    </Sec>
  )
}

function AppPasswords({ a, sec, mode }: { a: Who; sec?: AccountSecurity; mode: DetailMode }) {
  const pw = sec?.appPasswords ?? []
  return (
    <Sec title="App passwords" digest={!sec ? '…' : pw.length ? pw.map((p) => p.name).join(', ') : 'none'} flush open={mode === 'page' && pw.length > 0}>
      {!pw.length ? (
        <div className="cx-empty">{sec ? 'This account has no app passwords.' : '…'}</div>
      ) : (
        <div className="cx-tw">
          <table className="cx-t compact">
            <tbody>
              {pw.map((p) => (
                <tr key={p.name}>
                  <td style={{ width: '100%' }}>
                    <b>{p.name}</b>
                  </td>
                  <td>{p.privileged && <Chip k="warn">privileged</Chip>}</td>
                  <td className="r t2" title={p.createdAt}>
                    created {iso(p.createdAt)}
                  </td>
                  <td className="r">
                    <button type="button" className="cx-btn sm quiet" onClick={() => act.revokeAppPassword(a, p.name)}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Sec>
  )
}

/** A click-to-run load for a KV row: the button goes in the row's action slot, the answer in its value. */
function useOnDemand<T>(run: (refresh: boolean) => Promise<T>) {
  const [busy, setBusy] = useState(false)
  const [r, setR] = useState<T>()
  const go = async (refresh: boolean) => {
    setBusy(true)
    try {
      setR(await run(refresh))
    } catch (e) {
      toast(errText(e), { err: true })
    } finally {
      setBusy(false)
    }
  }
  const button = (label: string, refresh = false) => (
    <button type="button" className="cx-btn sm" disabled={busy} onClick={() => go(refresh)}>
      {busy && <Spinner />}
      {label}
    </button>
  )
  return { r, button }
}

type RepoCheck = { ok: boolean; problems?: string[]; records?: { count: number } }

/** Check repo: a row of its own, the verdict as its chip. */
function useCheckRepo(did: string): KVRow {
  const c = useOnDemand<RepoCheck>(() => admin('vlpds.admin.checkRepo', { params: { did } }))
  const r = c.r
  return [
    'Integrity',
    r ? (
      <div className="cx-acc-check">
        head signature, records, MST and indexes
        {!!r.problems?.length && (
          <ul>
            {r.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        )}
      </div>
    ) : (
      <span className="muted">head signature, records, MST and indexes, on request</span>
    ),
    { chip: r ? r.ok ? <Chip k="ok">ok</Chip> : <Chip k="err">{plural(r.problems?.length ?? 0, 'problem')}</Chip> : undefined, act: c.button(r ? 'Check again' : 'Check repo') },
  ]
}

/** The DID document's keys and the directory's rotation keys: one directory request, so only on a click. */
function useAccountKeys(did: string): KVRow {
  const c = useOnDemand((refresh) => withAdmin((x) => api.getAccountKeys(x, did, refresh)))
  const k = c.r
  if (!k) return ['Keys', <span className="muted">the DID document’s keys and rotation keys, on request</span>, { act: c.button('Show keys') }]
  return [
    'Keys',
    <div className="cx-acc-keys">
      {(k.verificationMethods ?? []).map((m) => (
        <div key={m.id} title={m.type}>
          <span className="muted sm">{m.id.replace(did, '')}</span> <Copy text={m.publicKeyMultibase ?? ''} />{' '}
          {m.matchesAccount ? <Chip k="ok">matches</Chip> : <Chip k="err">not the account’s key</Chip>}
        </div>
      ))}
      {k.didDocError && <div className="t2 sm">DID document: {k.didDocError}</div>}
      {k.pendingSigningKey && (
        <div>
          <span className="muted sm">pending</span> <Copy text={k.pendingSigningKey} />
        </div>
      )}
      {(k.rotationKeys ?? []).map((r, i) => (
        <div key={r.didKey}>
          <span className="muted sm">rotation {i + 1}</span> <Copy text={r.didKey} />{' '}
          <Chip k={r.role === 'other' ? 'plain' : 'acc'}>{r.role === 'server' ? 'this PDS' : r.role === 'operator_recovery' ? 'operator recovery' : 'other'}</Chip>
        </div>
      ))}
      {k.rotationKeysError && <div className="t2 sm">Rotation keys: {k.rotationKeysError}</div>}
    </div>,
    { act: c.button('Refetch', true) },
  ]
}

function Placement({ did, row, mode }: { did: string; row?: AccountRow; mode: DetailMode }) {
  const { view } = useClusterView()
  const check = useCheckRepo(did)
  if (!row) return null
  const owner = view?.nodes.find((n) => n.node === row.node)
  const pos = view?.raw.layout ? view.raw.layout.shards.findIndex((s) => s.id === row.shard) : row.shard
  return (
    <Sec title="Placement" digest={`shard ${row.shard} on ${row.node}`} open={mode === 'page'}>
      <KV
        rows={[
          [
            'Shard',
            <span className="mono">{String(row.shard).padStart(10, '0')}</span>,
            {
              act:
                pos !== undefined && pos >= 0 ? (
                  <button type="button" className="cx-btn sm quiet" onClick={() => openPanel('shard', String(pos))}>
                    Open shard ›
                  </button>
                ) : undefined,
            },
          ],
          [
            'Owner',
            owner ? (
              <Open type="node" id={owner.node}>
                <NodeTag n={owner} />
              </Open>
            ) : (
              <span className="mono">{row.node}</span>
            ),
          ],
          ['Repo rev', <span className="mono">{row.rev ?? '—'}</span>],
          ['Last commit', when(row.lastCommitAt)],
          ['Records', row.records === undefined ? '—' : fmtNum(row.records)],
          ['MST nodes', row.mstNodes === undefined ? '—' : fmtNum(row.mstNodes)],
          [
            'Repo size',
            <span title="Record blocks + MST node blocks, kept close by each commit; a recount makes it exact">
              {row.repoBytes === undefined ? (
                '—'
              ) : (
                <>
                  {fmtBytes(row.repoBytes)}{' '}
                  <span className="muted">
                    ({fmtBytes(row.recordBytes ?? 0)} records · {fmtBytes(row.mstBytes ?? 0)} MST)
                  </span>
                </>
              )}
            </span>,
            { act: btn('Recount…', () => act.recountRepo({ did: row.did, handle: row.handle, node: row.node })) },
          ],
          check,
        ]}
      />
    </Sec>
  )
}

function opRows(r: RepoOpsResult) {
  const out: { key: string; at?: string | null; kind: string; cls: string; path: string; seq: string }[] = []
  for (const e of r.events) {
    if (e.kind === 'commit') e.ops.forEach((o, i) => out.push({ key: `${e.seq}/${i}`, at: e.time, kind: o.action, cls: o.action === 'create' ? 'op-c' : o.action === 'update' ? 'op-u' : 'op-d', path: o.path, seq: e.seq }))
    else out.push({ key: e.seq, at: e.time, kind: `#${e.kind}`, cls: '', path: e.kind === 'identity' ? (e.handle ?? '') : e.kind === 'account' ? (e.active ? 'active' : (e.status ?? 'inactive')) : `rev ${e.rev}`, seq: e.seq })
  }
  return out
}

/** The account's newest commits and events from the firehose ring (also in Moderation's subject drawer). */
export function Ops({ did, mode, open }: { did: string; mode: DetailMode; open?: boolean }) {
  const v = useAccountsVersion()
  const n = mode === 'page' ? 40 : 12
  const l = useLoad(() => withAdmin((c) => api.listRepoOps(c, did, n)), [did, n, v])
  const rows = l.data ? opRows(l.data) : []
  const first = rows[0]
  return (
    <Sec title="Recent operations" digest={!l.data ? '…' : first ? `${first.kind} ${first.path.split('/')[0]} ${iso(first.at)}` : 'none in memory'} flush open={open ?? mode === 'page'} right={<Src>listRepoOps · firehose ring</Src>}>
      {l.error ? (
        isUnsupported(l.error) ? <NeedsVersion what="Recent operations" nsid="vlpds.admin.listRepoOps" /> : <ErrorState error={l.error} retry={l.reload} />
      ) : !l.data ? (
        <Loading />
      ) : !rows.length ? (
        <div className="cx-empty">Nothing for this account in the firehose ring{l.data.reachesBackToTime ? ` (back to ${ago(l.data.reachesBackToTime)})` : ''}.</div>
      ) : (
        <>
          <div className="cx-tw">
            <table className="cx-t compact">
              <tbody>
                {rows.map((o) => (
                  <tr key={o.key} data-open={`event:${o.seq}`} onClick={() => openPanel('event', o.seq)} style={{ cursor: 'pointer' }}>
                    <td>{iso(o.at)}</td>
                    <td className={`mono sm ${o.cls}`}>{o.kind}</td>
                    <td className="mono sm trunc" style={{ maxWidth: 280 }}>
                      {o.path}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="cx-pn-f">
            {l.data.ringExhausted ? 'Everything in memory' : `Back to seq ${l.data.reachesBackTo ?? '—'}`}
            {l.data.reachesBackToTime ? ` · ${ago(l.data.reachesBackToTime)}` : ''}
          </div>
        </>
      )}
    </Sec>
  )
}

function Blobs({ a, row, mode }: { a: Who; row?: AccountRow; mode: DetailMode }) {
  const v = useAccountsVersion()
  const l = useLoad<SubjectDetail>(() => admin('vlpds.admin.getSubject', { params: { did: a.did } }), [a.did, v])
  const q = l.data?.quota
  const pct = q && q.limitBytes ? (q.bytes / q.limitBytes) * 100 : undefined
  return (
    <Sec title="Blobs & quota" digest={q ? `${fmtBytes(q.bytes)}${q.limitBytes ? ` of ${fmtBytes(q.limitBytes)}` : ''}` : row ? fmtBytes(row.blobBytes) : '…'} open={mode === 'page'} right={<Src>getSubject · setBlobQuota</Src>}>
      {l.error ? (
        <ErrorState error={l.error} retry={l.reload} />
      ) : !q ? (
        <Loading />
      ) : (
        <>
          <KV
            rows={[
              ['Blobs', row?.blobs !== undefined ? fmtNum(row.blobs) : '—'],
              [
                'Stored',
                q.limitBytes > 0 ? (
                  <span className="cx-acc-quota">
                    <span>
                      {fmtBytes(q.bytes)} <span className="muted">of {fmtBytes(q.limitBytes)}</span>
                    </span>
                    <Meter v={q.bytes} max={q.limitBytes} k={q.over ? 'err' : pct! >= 80 ? 'warn' : undefined} wide />
                  </span>
                ) : (
                  <>
                    {fmtBytes(q.bytes)} <span className="muted">· no limit</span>
                  </>
                ),
                { chip: q.limitBytes > 0 ? q.over ? <Chip k="err">over</Chip> : <span className="mono sm t2">{pct!.toFixed(0)}%</span> : undefined },
              ],
              ['Uploads today', `${fmtNum(q.uploadsToday)}${q.limitUploadsPerDay ? ` of ${fmtNum(q.limitUploadsPerDay)}` : ''}`],
              [
                'Limits',
                q.override.bytes !== undefined || q.override.uploadsPerDay !== undefined ? 'set for this account' : 'server defaults',
                { chip: q.override.bytes !== undefined || q.override.uploadsPerDay !== undefined ? <Chip k="info">custom</Chip> : undefined, act: btn('Change quota…', () => act.setQuota(a, q)) },
              ],
            ]}
          />
        </>
      )}
    </Sec>
  )
}

function Invites({ a, info }: { a: Who; info?: AccountInfo }) {
  const codes = info?.invites ?? []
  return (
    <Sec title="Invites" digest={!info ? '…' : info.invitesDisabled ? 'blocked from creating codes' : plural(codes.length, 'code')} right={<Src>getAccountInfo</Src>}>
      <KV
        rows={[
          [
            'Creating codes',
            info?.invitesDisabled ? <span className="t2">blocked</span> : 'allowed',
            { chip: info ? onOff(!info.invitesDisabled, 'allowed') : undefined, act: info && btn(info.invitesDisabled ? 'Allow invites…' : 'Block invites…', () => act.setInvites(a, !!info.invitesDisabled)) },
          ],
          ['Invited with', <span className="mono sm">{info?.invitedBy?.code ?? '—'}</span>],
        ]}
      />
      {codes.length > 0 && (
        <div style={{ marginTop: 8 }}>
          {codes.map((c) => (
            <RRow key={c.code} x={`${c.uses.length}/${c.available} used${c.disabled ? ' · disabled' : ''}`}>
              <span className="mono sm">{c.code}</span>
            </RRow>
          ))}
        </div>
      )}
    </Sec>
  )
}

type AccountSpaces = {
  repos: { space: string; records: number; rev: { rev: string; at?: string } | null; takendownRecords: number }[]
  governs: { uri: string; createdAt: string; deletedAt?: string | null; takendown: boolean }[]
  more: boolean
}
const spaceLabel = (uri: string) => {
  const p = uri.replace(/^at:\/\//, '').split('/')
  return `${p[2]} / ${p[3]}`
}
const spacePath = (uri: string) => `/admin/spaces/space?uri=${encodeURIComponent(uri)}`

function Spaces({ did }: { did: string }) {
  const l = useLoad<AccountSpaces | null>(async () => {
    const d = await call('com.atproto.server.describeServer')
    if (!d?.vlpds?.spaces) return null
    return admin('vlpds.admin.getAccountSpaces', { params: { did } })
  }, [did])
  if (l.data === null) return null
  const d = l.data
  return (
    <Sec title="Spaces" digest={!d ? '…' : d.governs.length ? `authority of ${plural(d.governs.length, 'space')}` : d.repos.length ? `writes in ${plural(d.repos.length, 'space')}` : 'none'} right={<Src>getAccountSpaces</Src>}>
      {l.error ? (
        <ErrorState error={l.error} retry={l.reload} />
      ) : !d ? (
        <Loading />
      ) : d.governs.length + d.repos.length === 0 ? (
        <div className="t2">In no spaces.</div>
      ) : (
        <>
          {d.governs.map((g) => (
            <RRow key={`g${g.uri}`} to={spacePath(g.uri)} x={g.takendown ? 'taken down' : g.deletedAt ? 'deleted' : 'authority'}>
              <b className="nm">{spaceLabel(g.uri)}</b>
            </RRow>
          ))}
          {d.repos.map((r) => (
            <RRow key={`r${r.space}`} to={spacePath(r.space)} x={`${plural(r.records, 'record')}${r.takendownRecords ? ` · ${r.takendownRecords} down` : ''}`}>
              <span className="nm">{spaceLabel(r.space)}</span>
            </RRow>
          ))}
          {d.more && <div className="t2 sm">Showing the first 1,000.</div>}
        </>
      )}
    </Sec>
  )
}

type Case = { id: string; createdAt: string; status: string; source: string; subjects: { kind: string; did: string }[] }
type Audit = { id: string; at: string; actor: string; auth?: string; action: string; reason?: string; caseId?: string }

function Moderation({ did, status, mode }: { did: string; status?: SubjectStatus; mode: DetailMode }) {
  const v = useAccountsVersion()
  const cases = useLoad(async () => (await admin<{ cases: Case[] }>('vlpds.admin.listCases', { params: { did } })).cases, [did, v])
  const audit = useLoad(async () => (await admin<{ entries: Audit[] }>('vlpds.admin.getAuditLog', { params: { did, limit: 10 } })).entries, [did, v])
  const cs = cases.data ?? []
  const open = cs.filter((c) => c.status === 'open').length
  return (
    <Sec
      title="Moderation"
      digest={`${status?.takedown?.applied ? 'taken down · ' : ''}${cases.data ? (cs.length ? `${plural(cs.length, 'case')}${open ? `, ${open} open` : ''}` : 'no cases') : '…'}`}
      open={mode === 'page' && (cs.length > 0 || !!status?.takedown?.applied)}
      right={<Src>getSubjectStatus · listCases · getAuditLog</Src>}
    >
      <KV
        rows={[
          [
            'Takedown',
            status?.takedown?.applied ? <span className="mono sm">{status.takedown.ref ?? 'no reference'}</span> : <span className="muted">none</span>,
            {
              chip: status?.takedown?.applied ? <Chip k="err">in effect</Chip> : undefined,
              act: (
                <Link className="cx-btn sm quiet" to={`/admin/moderation?q=${encodeURIComponent(did)}`}>
                  Moderation ›
                </Link>
              ),
            },
          ],
          ['Deactivated', status?.deactivated?.applied ? 'yes' : <span className="muted">no</span>, { chip: status?.deactivated?.applied ? <Chip k="warn">deactivated</Chip> : undefined }],
        ]}
      />
      {!!cases.error && <ErrorState error={cases.error} retry={cases.reload} />}
      {cs.map((c) => (
        <RRow key={c.id} to={`/admin/moderation/cases/${encodeURIComponent(c.id)}`} x={c.status}>
          <span className="mono sm">{c.id}</span>
          <span className="nm t2">{c.source}</span>
        </RRow>
      ))}
      {!!audit.data?.length && (
        <>
          <div className="cx-eyebrow" style={{ marginTop: 10 }}>
            Audit log
          </div>
          {audit.data.map((e) => (
            <RRow key={e.id} x={iso(e.at)} title={e.reason}>
              <AuditAction a={e.action} />
              <span className="nm t2" title={authName(e.auth)}>{e.actor}</span>
            </RRow>
          ))}
        </>
      )}
    </Sec>
  )
}

/** The account's mail in the nodes' logs (kept in memory, the last 200 per node): purpose and outcome, no address or code. */
function AccountMail({ did, l }: { did: string; l: Load<MailEntry[]> }) {
  const ms = l.data ?? []
  return (
    <Sec title="Mail" digest={!l.data ? (l.error ? 'unavailable' : '…') : ms.length ? `${purposeLabel(ms[0].purpose)} ${ago(ms[0].at)} · ${mailOutcome(ms[0])}` : 'none in the log'} flush right={<Src>listMail · did</Src>}>
      {l.error ? (
        isUnsupported(l.error) ? <NeedsVersion what="The mail log" nsid="vlpds.admin.listMail" /> : <ErrorState error={l.error} retry={l.reload} />
      ) : !l.data ? (
        <Loading />
      ) : !ms.length ? (
        <div className="cx-empty">No mail for this account since the nodes started.</div>
      ) : (
        <>
          {ms.slice(0, 6).map((m) => (
            <RRow key={mailId(m)} onClick={() => openPanel('mail', mailId(m))} x={<MailChip m={m} />}>
              <span className="t2 sm" style={{ minWidth: 56 }}>
                {ago(m.at)}
              </span>
              <span className="nm">{purposeLabel(m.purpose)}</span>
              <span className="muted sm">…@{m.toDomain}</span>
            </RRow>
          ))}
          <div className="cx-pn-f">
            <Link to={`/admin/mail?did=${encodeURIComponent(did)}`}>All of this account’s mail ›</Link>
          </div>
        </>
      )}
    </Sec>
  )
}

function DevMail({ email }: { email: string }) {
  const m = useLoad<{ messages?: unknown[]; token?: string }>(() => admin('vlpds.admin.getDevMail', { params: { email } }), [email])
  if (m.error || !m.data) return null
  const msgs = m.data.messages ?? []
  return (
    <Sec title="Dev mailbox" digest={plural(msgs.length, 'message')}>
      {m.data.token && (
        <KV rows={[['Latest code', <Copy text={m.data.token} />]]} />
      )}
      {msgs.length ? <Json value={msgs.slice(-3).reverse()} /> : <div className="t2">Nothing sent yet.</div>}
    </Sec>
  )
}

function Danger({ a, row, status, mode }: { a: Who; row?: AccountRow; status?: SubjectStatus; mode: DetailMode }) {
  const taken = !!status?.takedown?.applied || row?.status === 'takendown'
  const deact = !!status?.deactivated?.applied || row?.status === 'deactivated'
  return (
    <Sec title="Danger zone" digest="each asks you to type the handle" danger flush open={mode === 'page'}>
      <div className="cx-acts">
        {taken ? (
          <Act t="Reverse takedown" d="Serve the repo again and send an #account event.">
            {btn('Reverse…', () => act.reverseTakedown(a))}
          </Act>
        ) : (
          <Act t="Take down" d="Hide the repo from the network and revoke every session.">
            {btn('Take down…', () => act.takeDown(a), true)}
          </Act>
        )}
        {deact ? (
          <Act t="Reactivate" d="Serve the repo again and cancel a scheduled deletion.">
            {btn('Reactivate…', () => act.reactivate(a))}
          </Act>
        ) : (
          <Act t="Deactivate" d="Stop serving the repo until it's reactivated.">
            {btn('Deactivate…', () => act.deactivate(a), true)}
          </Act>
        )}
        <Act t="Rotate signing key" d="New repo key, PLC update, re-signed head.">
          {btn('Rotate…', () => act.rotateKey(a), true)}
        </Act>
        <Act t="Rebuild repo" d="Re-derive from records under a new signed commit and a #sync.">
          {btn('Rebuild…', () => act.rebuildRepo(a).catch((e) => toast(errText(e), { err: true })), true)}
        </Act>
        <Act t="Delete account" d="Erase the repo, blobs and account record. No undo.">
          {btn('Delete…', () => act.deleteAccount(a, { records: row?.records, blobs: row?.blobs }), true)}
        </Act>
      </div>
    </Sec>
  )
}

function Identity({ a, i, r }: { a: Who; i?: AccountInfo; r?: AccountRow }) {
  const did = a.did
  const keys = useAccountKeys(did)
  return (
    <Sec title="Identity" digest={did} open right={<Src>getAccountInfo</Src>}>
      <KV
        rows={[
          ['DID', <Copy text={did} />],
          ['Handle', `@${a.handle}`, { act: btn('Change…', () => act.setHandle(a)) }],
          [
            'Email',
            i?.email ? <Copy text={i.email} mono={false} /> : <span className="muted">none</span>,
            i?.email ? { chip: i.emailConfirmedAt ? <Chip k="ok">confirmed</Chip> : <Chip k="warn">unconfirmed</Chip>, act: btn('Change…', () => act.setEmail(a, i.email)) } : {},
          ],
          [
            'Created',
            i ? (
              <>
                {date(i.indexedAt)} <span className="muted">({iso(i.indexedAt)})</span>
              </>
            ) : (
              '—'
            ),
          ],
          ['Second factors', r ? <TwoFactor f={r.secondFactors} /> : '—'],
          [
            'PLC',
            did.startsWith('did:plc:') ? (
              <a href={`https://plc.directory/${did}/log/audit`} target="_blank" rel="noreferrer">
                audit log ↗
              </a>
            ) : (
              <span className="mono sm">{did.split(':').slice(0, 2).join(':')}</span>
            ),
          ],
          keys,
          ['#identity', <span className="muted">tells relays and AppViews to re-resolve the DID and handle</span>, { act: btn('Publish…', () => act.publishIdentity(a)) }],
        ]}
      />
    </Sec>
  )
}

// ---------------------------------------------------------------- the detail

function useAccount(did: string) {
  const v = useAccountsVersion()
  const row = useLoad<AccountRow | undefined>(async () => {
    try {
      const r = await withAdmin((c) => api.listAccounts(c, { q: did, limit: 1 }))
      return r.accounts.find((x) => x.did === did)
    } catch (e) {
      if (isUnsupported(e)) return undefined
      throw e
    }
  }, [did, v])
  const info = useLoad<AccountInfo>(() => admin('com.atproto.admin.getAccountInfo', { params: { did } }), [did, v])
  const status = useLoad<SubjectStatus>(() => admin('com.atproto.admin.getSubjectStatus', { params: { did } }), [did, v])
  const sec = useLoad<AccountSecurity>(() => withAdmin((c) => api.getAccountSecurity(c, did)), [did, v])
  const sessions = useLoad(() => withAdmin((c) => api.listSessions(c, did)), [did, v])
  const mail = useLoad(async () => (await withAdmin((c) => api.listMail(c, 20, undefined, did))).mail, [did, v])
  return { row, info, status, sec, sessions, mail }
}

function banners(a: Who, row: AccountRow | undefined, info: AccountInfo | undefined, status: SubjectStatus | undefined, sec: AccountSecurity | undefined): BannerSpec[] {
  const out: BannerSpec[] = []
  const locks = (sec?.lockouts ?? []).filter((l) => l.lockedUntil && l.lockedUntil > Date.now())
  if (locks.length)
    out.push({
      id: 'locked',
      tone: 'warn',
      title: 'Sign-in codes locked',
      desc: `${locks.map((l) => factorName(l.factor)).join(' and ')} after wrong codes · clears ${ago(Math.max(...locks.map((l) => l.lockedUntil!)))} · live sessions keep working`,
      right: btn('Unlock…', () => act.clearLockout(a)),
    })
  if (status?.takedown?.applied) out.push({ id: 'td', tone: 'err', title: 'Taken down', desc: `${status.takedown.ref ? `${status.takedown.ref} · ` : ''}repo hidden, sessions revoked`, right: btn('Reverse…', () => act.reverseTakedown(a)) })
  if (info?.deletionScheduledAt) out.push({ id: 'del', tone: 'err', title: 'Deactivated, deletion scheduled', desc: `deleted ${ago(new Date(info.deletionScheduledAt).getTime())} unless the owner reactivates` })
  else if (info?.deactivatedAt && !status?.takedown?.applied) out.push({ id: 'deact', tone: 'warn', title: 'Deactivated', desc: `since ${date(info.deactivatedAt)} · the repo isn't served`, right: btn('Reactivate…', () => act.reactivate(a)) })
  if (row?.overQuota) out.push({ id: 'quota', tone: 'warn', title: 'Over its blob quota', desc: `${fmtBytes(row.blobBytes)} · new uploads refused` })
  if (info?.email && !info.emailConfirmedAt) out.push({ id: 'email', tone: 'warn', title: 'Email not confirmed', desc: 'actions that need a confirmed email are refused' })
  return out
}

registerDetail('account', {
  kind: 'Account',
  section: 'accounts',
  use: (did, mode) => {
    const { row, info, status, sec, sessions, mail } = useAccount(did)
    const rl = rlPoll.use()
    const r = row.data
    const i = info.data
    const handle = i?.handle ?? r?.handle
    // a deleted account keeps its last data in the load, so check the error first
    const gone = !!info.error && ((info.error as { status?: number }).status === 404 || /not found/i.test(errText(info.error)))
    if (gone) return { title: <span className="mono">{shortDid(did)}</span>, body: null, missing: 'No account with this DID on this PDS.' }
    if (info.error && !i) return { title: <span className="mono">{shortDid(did)}</span>, body: null, missing: <ErrorState error={info.error} retry={info.reload} /> }
    if (!handle) return { title: <span className="mono">{shortDid(did)}</span>, body: null, loading: true }
    const a: Who = { did, handle, node: r?.node }
    const [k, t] = accountState(r ?? { status: status.data?.takedown?.applied ? 'takendown' : i?.deactivatedAt ? 'deactivated' : 'active', deleteAfter: i?.deletionScheduledAt })
    const s = sec.data
    const lastGood = s?.recentSignIns.find((x) => !x.failed)
    const held = heldSignInKeys(rl.data, { did, handle, email: i?.email ?? r?.email })
    // the newest sign-in-related mail: what support asks about first
    const signInMail = mail.data?.find((m) => m.purpose === 'reset_password' || m.purpose === 'auth_factor' || m.purpose === 'confirm_email')

    const strip = (
      <Strip
        items={[
          ['sessions', sessions.data ? fmtNum(sessions.data.sessions.length) : '—'],
          ['last sign-in', s ? (lastGood ? ago(lastGood.at) : 'none in 30 d') : '—'],
          ['records', r?.records === undefined ? '—' : fmtNum(r.records)],
          ['repo', r?.repoBytes === undefined ? '—' : fmtBytes(r.repoBytes)],
          [`blobs · ${r ? fmtBytes(r.blobBytes) : '—'}`, r?.blobs === undefined ? '—' : fmtNum(r.blobs)],
          ['last commit', when(r?.lastCommitAt)],
        ]}
      />
    )
    const identity = <Identity a={a} i={i} r={r} />
    const placement = <Placement did={did} row={r} mode={mode} />
    const security = <Security a={a} sec={sec} />
    const signIns = <SignIns sec={sec} mode={mode} />
    const sessionsSec = <Sessions a={a} l={sessions} mode={mode} />
    const mailSec = <AccountMail did={did} l={mail} />
    const apppw = <AppPasswords a={a} sec={s} mode={mode} />
    const ops = <Ops did={did} mode={mode} />
    const blobs = <Blobs a={a} row={r} mode={mode} />
    const invites = <Invites a={a} info={i} />
    const spaces = <Spaces did={did} />
    const moder = <Moderation did={did} status={status.data} mode={mode} />
    const dev = i?.email ? <DevMail email={i.email} /> : null
    const danger = <Danger a={a} row={r} status={status.data} mode={mode} />
    const top = (
      <>
        <Banners items={banners(a, r, i, status.data, s)} />
        <CanSignIn a={a} k={k} t={t} i={i} sec={sec} held={held} mail={signInMail} />
        {strip}
      </>
    )
    return {
      wide: true,
      title: `@${handle}`,
      chip: <Chip k={k}>{t}</Chip>,
      foot: (
        <>
          <Src>listAccounts · getAccountInfo · getSubjectStatus</Src> {r ? `on ${r.node}, shard ${r.shard}` : ''}
        </>
      ),
      body:
        mode === 'page' ? (
          <>
            {top}
            <div className="cols">
              <div>{identity}</div>
              <div>{security}</div>
            </div>
            {signIns}
            {sessionsSec}
            <div className="cols">
              <div>
                {placement}
                {blobs}
                {ops}
                {spaces}
              </div>
              <div>
                {apppw}
                {invites}
                {mailSec}
                {moder}
                {dev}
                {danger}
              </div>
            </div>
          </>
        ) : (
          <>
            {top}
            {identity}
            {security}
            {signIns}
            {sessionsSec}
            {placement}
            {apppw}
            {ops}
            {blobs}
            {invites}
            {spaces}
            {mailSec}
            {moder}
            {dev}
            {danger}
          </>
        ),
    }
  },
})

// ---------------------------------------------------------------- ⌘K

const VERBS: { re: RegExp; label: string; run: (a: Who, r: AccountRow) => unknown }[] = [
  { re: /^take ?down$/, label: 'Take down', run: (a) => act.takeDown(a) },
  { re: /^(reverse|undo)( takedown)?$/, label: 'Reverse the takedown of', run: (a) => act.reverseTakedown(a) },
  { re: /^deactivate$/, label: 'Deactivate', run: (a) => act.deactivate(a) },
  { re: /^reactivate$/, label: 'Reactivate', run: (a) => act.reactivate(a) },
  { re: /^(reset 2fa|reset)$/, label: 'Reset two-factor for', run: (a) => act.resetSecondFactors(a) },
  { re: /^sign ?out$/, label: 'Sign out everywhere:', run: (a) => act.signOutEverywhere(a) },
  { re: /^rotate( key)?$/, label: 'Rotate the signing key of', run: (a) => act.rotateKey(a) },
  { re: /^rebuild( repo)?$/, label: 'Rebuild the repo of', run: (a) => act.rebuildRepo(a).catch((e) => toast(errText(e), { err: true })) },
  { re: /^unlock$/, label: 'Unlock sign-in codes for', run: (a) => act.clearLockout(a) },
  { re: /^delete$/, label: 'Delete', run: (a, r) => act.deleteAccount(a, { records: r.records, blobs: r.blobs }) },
]
const VERB_RE = /^(take ?down|reverse takedown|reverse|undo|deactivate|reactivate|reset 2fa|reset|sign ?out|rotate key|rotate|rebuild repo|rebuild|unlock|delete)\s+@?(\S+)$/i

// "take down @handle", "reset 2fa alice", "delete did:plc:…": one item per matching account
registerPalette({
  items: () => [],
  async: async (q, signal): Promise<PalItem[]> => {
    const m = VERB_RE.exec(q.trim())
    if (!m) return []
    const verb = VERBS.find((v) => v.re.test(m[1].toLowerCase()))
    if (!verb) return []
    const r = await withAdmin((c) => api.listAccounts(c, { q: m[2], limit: 8 }, signal))
    return r.accounts.map((x) => {
      const [k] = accountState(x)
      return {
        group: 'Actions',
        glyph: <span className={`cx-g s-${k === 'acc' || k === 'plain' || k === 'violet' || k === 'stale' ? 'idle' : k}`}>■</span>,
        title: `${verb.label} @${x.handle}…`,
        desc: 'typed confirm',
        hay: x.did,
        run: () => {
          openPanel('account', x.did)
          verb.run({ did: x.did, handle: x.handle, node: x.node }, x)
        },
      }
    })
  },
})
