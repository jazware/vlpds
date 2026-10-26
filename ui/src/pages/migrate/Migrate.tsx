import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { BrandFooter, CopyText, DomainAffix, ErrorNotice, Field, Notice, Spinner, Status, Topbar } from '../../components/ui'
import { RecoveryKeyExplainer, RecoveryKeyPicker, type RecoveryKeyChoice } from '../../components/RecoveryKey'
import { BackupBox } from '../../components/Backup'
import { canStreamToDisk, type BackupSource } from '../../lib/backup'
import * as I from '../../components/icons'
import { fmtBytes, fmtNum } from '../../lib/format'
import { useLoad } from '../../lib/hooks'
import { Link, navigate, useSearch } from '../../lib/router'
import { call, errText, setSession, XrpcError } from '../../lib/xrpc'
import {
  clearSecrets,
  copyBlobs,
  copyRepo,
  DidWeb,
  findAccount,
  HandleUnresolved,
  keepSignedOp,
  loadSaved,
  Pds,
  pdsOf,
  shortKey,
  signedOp,
  signingKeyOf,
  STEPS,
  storeSaved,
  type AccountStatus,
  type DidDoc,
  type Found,
  type Saved,
  type StepId,
} from './flow'
import type { RecordCounts } from './count'
import { BLOB_SCOPE, copySpace, NEW_SCOPE, OLD_SCOPE, plan, reasonOf, servesSpaces, spaceLabel, type SpaceMove, type SpacePlan } from './spaces'
import { beginSignIn, clientInfo, finishSignIn, forgetAll, isCallback, OAuthSession, sweepKeys } from '../../lib/oauth'

type Describe = { did: string; availableUserDomains: string[]; inviteCodeRequired?: boolean }

const here = location.host

/** Advanced mode shows the protocol details (DIDs, keys, counts, raw
 * errors); simple mode, the default, the same flow in plain words. */
const Adv = createContext(false)
const useAdv = () => useContext(Adv)
const MODE_KEY = 'vlpds.migrate.advanced'

function loadAdvanced(): boolean {
  try {
    return localStorage.getItem(MODE_KEY) === '1'
  } catch {
    return false
  }
}

function storeAdvanced(on: boolean) {
  try {
    if (on) localStorage.setItem(MODE_KEY, '1')
    else localStorage.removeItem(MODE_KEY)
  } catch {
    /* this tab only */
  }
}

/** The simple mode's rail: fewer, bigger steps over the same state machine. */
const SIMPLE_STEPS: { label: string; ids: StepId[] }[] = [
  { label: 'Find your account', ids: ['find', 'signin'] },
  { label: 'Get ready', ids: ['check', 'handle', 'create'] },
  { label: 'Copy your posts and photos', ids: ['copy'] },
  { label: 'Save a copy (optional)', ids: ['backup'] },
  { label: 'Switch over', ids: ['identity', 'finish'] },
]

/** Moves an account from another PDS (the reference implementation, or
 * anything speaking the same XRPC) to this one, in the browser: the old
 * server is called directly (the reference PDS allows CORS from anywhere). */
export function Migrate() {
  const q = useSearch()
  const describe = useLoad<Describe>(() => call('com.atproto.server.describeServer'), [])
  const [advanced, setAdvancedRaw] = useState(loadAdvanced)
  const setAdvanced = (on: boolean) => {
    storeAdvanced(on)
    setAdvancedRaw(on)
  }
  const [saved, setSavedRaw] = useState<Saved | null>(loadSaved)
  // only for "use the same password here"; never stored
  const [oldPassword, setOldPassword] = useState('')
  const [resumeAsked, setResumeAsked] = useState(false)
  // back from an OAuth sign-in (the Spaces step): redeem the code first
  const [callback, setCallback] = useState(isCallback)
  const [oauthError, setOauthError] = useState<unknown>()
  useEffect(() => {
    if (!callback) {
      void sweepKeys(['old', 'new'])
      return
    }
    once('oauth-callback', finishSignIn)
      .catch(setOauthError)
      .finally(() => setCallback(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const [, bump] = useState(0)

  const update = useCallback((patch: Partial<Saved>) => {
    setSavedRaw((s) => {
      if (!s) return s
      const n = { ...s, ...patch }
      storeSaved(n)
      return n
    })
  }, [])
  const begin = (s: Saved) => {
    clearSecrets()
    storeSaved(s)
    setSavedRaw(s)
  }
  const reset = () => {
    storeSaved(null)
    clearSecrets()
    void forgetAll(['old', 'new'])
    setSavedRaw(null)
    setOldPassword('')
  }

  const oldPds = useMemo(() => (saved ? new Pds('old', saved.oldPds, saved.did) : null), [saved?.did, saved?.oldPds])
  const newPds = useMemo(() => (saved ? new Pds('new', '', saved.did) : null), [saved?.did])
  const refresh = () => bump((n) => n + 1)

  const invite = q.get('invite') ?? ''
  const step = currentStep(saved)
  const needOld = !!saved && step !== 'find' && step !== 'done' && !(step === 'finish' && saved.oldDeactivated) && !oldPds?.tokens
  const needNew = !!saved?.created && step !== 'done' && !newPds?.tokens
  // a reload in the same tab still has the sessions and goes on; a new tab asks first
  const needResume = !!saved && step !== 'done' && !resumeAsked && (needOld || needNew) && !!saved.checkedAt
  const railStep: StepId = needOld && !saved?.checkedAt ? 'signin' : step

  let body: ReactNode
  if (callback) {
    body = <Spinner label="Finishing the sign-in" />
  } else if (!describe.data) {
    body = describe.error ? <Notice kind="err">This server's info is unavailable ({errText(describe.error)}). Reload to try again.</Notice> : <Spinner />
  } else if (!saved) {
    body = <FindStep onFound={begin} invite={invite} />
  } else if (needResume) {
    body = <ResumeStep saved={saved} onContinue={() => setResumeAsked(true)} onReset={reset} />
  } else if (needOld) {
    body = <SignInStep side="old" saved={saved} pds={oldPds!} onDone={(pw) => (setOldPassword(pw), refresh())} onReset={reset} />
  } else if (needNew) {
    body = (
      <SignInStep
        side="new"
        saved={saved}
        pds={newPds!}
        onDone={(_pw, out) => {
          update({ newHandle: out.handle })
          refresh()
        }}
        onReset={reset}
      />
    )
  } else if (step === 'check') {
    body = <CheckStep saved={saved} describe={describe.data} oldPds={oldPds!} update={update} onReset={reset} />
  } else if (step === 'handle') {
    body = <HandleStep saved={saved} describe={describe.data} update={update} />
  } else if (step === 'create') {
    body = (
      <CreateStep saved={saved} describe={describe.data} oldPds={oldPds!} newPds={newPds!} oldPassword={oldPassword} invite={invite} update={update} />
    )
  } else if (step === 'copy') {
    body = <CopyStep saved={saved} oldPds={oldPds!} newPds={newPds!} update={update} />
  } else if (step === 'backup') {
    body = <BackupStep saved={saved} oldPds={oldPds!} update={update} />
  } else if (step === 'identity') {
    body = <IdentityStep saved={saved} oldPds={oldPds!} newPds={newPds!} update={update} />
  } else if (step === 'finish') {
    body = <FinishStep saved={saved} oldPds={oldPds!} newPds={newPds!} update={update} oauthError={oauthError} />
  } else {
    body = <DoneStep saved={saved} newPds={newPds!} onReset={reset} />
  }

  const rail = advanced
    ? STEPS.map((s) => ({ key: s.id, label: s.label, at: s.id === railStep, idx: STEPS.findIndex((x) => x.id === s.id) }))
    : SIMPLE_STEPS.map((g, i) => ({ key: g.label, label: g.label, at: g.ids.includes(railStep), idx: i }))
  const railAt = railStep === 'done' ? rail.length : rail.findIndex((r) => r.at)
  return (
    <Adv.Provider value={advanced}>
      <Topbar where="Move here" />
      <main className="mig">
        <aside className="mig-rail" aria-label="Steps">
          <ol>
            {rail.map((s, i) => {
              const state = i < railAt ? 'done' : i === railAt ? 'now' : 'todo'
              return (
                <li key={s.key} className={state} aria-current={state === 'now' ? 'step' : undefined}>
                  <span className="n">{state === 'done' ? <I.Check /> : i + 1}</span>
                  {s.label}
                </li>
              )
            })}
          </ol>
          {saved && (advanced ? <Standing saved={saved} /> : <SimpleStanding saved={saved} />)}
        </aside>
        <section className="mig-main">
          <label className="mig-mode check">
            <input type="checkbox" name="advanced" checked={advanced} onChange={(e) => setAdvanced(e.target.checked)} />
            <span>I'm familiar with AT Protocol: show the technical details</span>
          </label>
          {!!oauthError && !(saved?.activated && !saved.spaces) && <Problem error={oauthError} />}
          {body}
        </section>
        <BrandFooter />
      </main>
    </Adv.Provider>
  )
}

/** Plain words first; the server's own message behind "Show details". */
function Problem({ error }: { error: unknown }) {
  const adv = useAdv()
  if (!error) return null
  if (adv) return <ErrorNotice error={error} />
  const raw = error instanceof XrpcError ? `${error.error} (${error.status}): ${error.message}` : error instanceof Error ? error.message : String(error)
  return (
    <Notice kind="err">
      <p>{plainError(error)}</p>
      {raw !== plainError(error) && (
        <details className="mig-details">
          <summary>Show details</summary>
          <p className="mono small">{raw}</p>
        </details>
      )}
    </Notice>
  )
}

function plainError(e: unknown): string {
  if (e instanceof XrpcError) {
    if (e.status === 429 || e.error === 'RateLimitExceeded') return 'Too many tries for now. Wait a few minutes, then try again.'
    if (e.error === 'InvalidToken') return "That code isn't right. Check it and try again."
    if (e.error === 'ExpiredToken') return 'That code has expired. Ask for a new one.'
    if (e.error === 'AppPassword') return e.message
    if (e.error === 'AuthenticationRequired' || e.status === 401) return 'You were signed out. Reload the page and sign in again.'
    if (e.status >= 500) return 'A server had a problem. Wait a moment, then try again.'
    return "That didn't work. Try again; if it keeps happening, the details below can help whoever runs this server."
  }
  // our own messages (flow.ts) are already written for people
  if (e instanceof Error && !(e instanceof TypeError)) return e.message
  return "Couldn't reach a server. Check your connection and try again."
}

function SimpleStanding({ saved: s }: { saved: Saved }) {
  return (
    <div className="mig-standing" aria-label="Where things stand">
      <p>
        {s.identityDone ? (
          <>Your account now lives on {here}.</>
        ) : (
          <>
            Your account will be hosted at <b>{here}</b>. Until the last step, nothing changes: you can stop any time and keep using {hostOf(s.oldPds)}.
          </>
        )}
      </p>
    </div>
  )
}

function currentStep(s: Saved | null): StepId {
  if (!s) return 'find'
  if (s.finishedAt) return 'done'
  if (!s.checkedAt) return 'check'
  if (!s.newHandle) return 'handle'
  if (!s.created) return 'create'
  if (!(s.repoDone && s.blobsDone && s.prefsDone)) return 'copy'
  if (!s.backup && !s.identityDone) return 'backup'
  if (!s.identityDone) return 'identity'
  if (!(s.activated && s.oldDeactivated)) return 'finish'
  return 'done'
}

// ---------------------------------------------------------------- layout bits

function Card({ title, sub, children }: { title: string; sub?: ReactNode; children: ReactNode }) {
  return (
    <div className="mig-card">
      <h1>{title}</h1>
      {sub && <p className="sub">{sub}</p>}
      {children}
    </div>
  )
}

/** Both sides at a glance, so a stop at any point leaves no doubt where the account is. */
function Standing({ saved: s }: { saved: Saved }) {
  const oldHost = hostOf(s.oldPds)
  return (
    <div className="mig-standing" aria-label="Where things stand">
      <h2>Where things stand</h2>
      <dl>
        <dt>{oldHost}</dt>
        <dd>
          {s.oldDeactivated ? <Status kind="idle">Deactivated, kept as a fallback</Status> : <Status kind="ok">Active: your account today</Status>}
        </dd>
        <dt>{here}</dt>
        <dd>
          {s.activated ? (
            <Status kind="ok">Active</Status>
          ) : s.created ? (
            <Status kind="warn">Created, not live yet</Status>
          ) : (
            <Status kind="idle">Nothing yet</Status>
          )}
        </dd>
        <dt>Identity points to</dt>
        <dd className="mono">{s.identityDone ? here : oldHost}</dd>
      </dl>
      {!s.identityDone && <p>Until your identity moves, nothing changes for anyone else. You can stop here and keep using {oldHost}.</p>}
    </div>
  )
}

const hostOf = (u: string) => {
  try {
    return new URL(u).host
  } catch {
    return u
  }
}

/** English nouns with the reader's digit grouping; zeros are left out. */
const NOUNS = {
  posts: ['post', 'posts'],
  likes: ['like', 'likes'],
  follows: ['follow', 'follows'],
  reposts: ['repost', 'reposts'],
  media: ['photo or video', 'photos & videos'],
} as const
type Tally = Partial<Record<keyof typeof NOUNS, number>>

const noun = (k: keyof typeof NOUNS, n: number) => NOUNS[k][n === 1 ? 0 : 1]

function tally(t: Tally): string[] {
  return (Object.keys(NOUNS) as (keyof typeof NOUNS)[]).flatMap((k) => {
    const n = t[k]
    return n ? [`${fmtNum(n)} ${noun(k, n)}`] : []
  })
}

const andList = (xs: string[]) => (xs.length < 2 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`)

function Checkline({ state, title, children }: { state: 'ok' | 'warn' | 'bad' | 'wait'; title: string; children?: ReactNode }) {
  return (
    <li className={`mig-check ${state}`}>
      <span className="icon">{state === 'wait' ? <Spinner /> : state === 'ok' ? <I.Check /> : <I.Alert />}</span>
      <div>
        <strong>{title}</strong>
        {children && <div className="small muted">{children}</div>}
      </div>
    </li>
  )
}

function Bar({ value, total, label }: { value: number; total?: number; label: string }) {
  const pct = total ? Math.min(100, (value / total) * 100) : undefined
  return (
    <div className="mig-bar" role="progressbar" aria-label={label} aria-valuenow={pct !== undefined ? Math.round(pct) : undefined} aria-valuemin={0} aria-valuemax={100}>
      <div style={{ width: pct !== undefined ? `${pct}%` : '100%' }} className={pct === undefined ? 'indeterminate' : ''} />
    </div>
  )
}

/** Runs `fn` once per key even when React mounts twice (StrictMode) or the
 * component remounts mid-run: the second caller gets the same promise. */
const jobs = new Map<string, Promise<unknown>>()
function once<T>(key: string, fn: () => Promise<T>): Promise<T> {
  let p = jobs.get(key) as Promise<T> | undefined
  if (!p) {
    p = fn().finally(() => jobs.delete(key))
    jobs.set(key, p)
  }
  return p
}

// ---------------------------------------------------------------- 1. find

function FindStep({ onFound, invite }: { onFound: (s: Saved) => void; invite: string }) {
  const adv = useAdv()
  const [ident, setIdent] = useState('')
  const [host, setHost] = useState('')
  const [needHost, setNeedHost] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [already, setAlready] = useState<Found>()

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    setAlready(undefined)
    try {
      const f = await findAccount(ident, needHost ? host : undefined)
      if (f.pds === location.origin) {
        setAlready(f)
        return
      }
      let domains: string[] = []
      try {
        domains = (await call('com.atproto.server.describeServer', { base: f.pds })).availableUserDomains ?? []
      } catch (err) {
        throw new Error(`Your account's server, ${hostOf(f.pds)}, isn't answering (${errText(err)}). Check that it is online and try again.`)
      }
      onFound({
        did: f.did,
        oldPds: f.pds,
        oldHandle: f.handle,
        oldDomains: domains,
        invite: invite || undefined,
        startedAt: Date.now(),
      })
    } catch (err) {
      if (err instanceof HandleUnresolved) setNeedHost(true)
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title="Move your account here"
      sub={
        adv ? (
          <>
            Bring your Bluesky / atproto account to {here}: repository, blobs and preferences, then your DID's PLC entry. Your followers keep following
            you. Nothing changes for anyone else until the identity step.
          </>
        ) : (
          <>
            Bring your Bluesky account to {here}. Your posts, follows, likes, photos and settings come along, and your followers keep following you. It
            takes a few minutes, and nothing changes for anyone else until the last step.
          </>
        )
      }
    >
      <div className="mig-need">
        <strong>You'll need</strong>
        <ul>
          <li>Your account's <b>main password</b> (not an app password).</li>
          <li>Access to the <b>email</b> on your account: we'll email you a code to confirm the move.</li>
          <li>To keep this tab open while your data copies.</li>
        </ul>
      </div>
      <form onSubmit={submit}>
        {error instanceof DidWeb && !adv ? (
          <Notice kind="err">
            <p>
              This account's address is managed on its own website, so this page can't move it. Turn on the technical details above to see the manual
              steps.
            </p>
          </Notice>
        ) : error instanceof DidWeb ? (
          <Notice kind="err">
            <p>
              <b>{error.did}</b> is a did:web. Its DID document lives on a web server you control, so this page can't move it for you. Copy your data
              with the steps below, then update the <span className="mono">#atproto_pds</span> service and <span className="mono">#atproto</span> key in
              your <span className="mono">did.json</span> yourself.
            </p>
          </Notice>
        ) : error instanceof HandleUnresolved ? (
          <Notice kind="warn">
            {adv
              ? `We couldn't look up @${error.handle} from here. Enter your DID instead, or the address of the PDS your account is on now.`
              : `We couldn't look up @${error.handle} from here. Tell us where you sign in today (for example bsky.social).`}
          </Notice>
        ) : (
          <Problem error={error} />
        )}
        {already && (
          <Notice kind="ok">
            <p>
              @{already.handle} already lives on {here}. <Link to="/account">Sign in to manage it.</Link>
            </p>
          </Notice>
        )}
        <Field
          label={adv ? 'Your handle or DID' : 'Your account address'}
          hint={adv ? 'For example alice.bsky.social, your own domain, or did:plc:…' : 'Your handle, for example alice.bsky.social'}
        >
          <input
            type="text"
            name="identifier"
            value={ident}
            onChange={(e) => setIdent(e.target.value)}
            autoCapitalize="none"
            autoComplete="username"
            spellCheck={false}
            required
            autoFocus
          />
        </Field>
        {needHost && (
          <Field label="Your current server" hint="Where you sign in today, e.g. bsky.social or pds.example.com.">
            <input type="text" name="host" value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" spellCheck={false} />
          </Field>
        )}
        <div className="row end">
          <button type="submit" className="btn primary" disabled={busy}>
            {busy && <Spinner />}
            Find my account
          </button>
        </div>
      </form>
    </Card>
  )
}

// ---------------------------------------------------------------- resume / sign in

function ResumeStep({ saved, onContinue, onReset }: { saved: Saved; onContinue: () => void; onReset: () => void }) {
  const adv = useAdv()
  const [sure, setSure] = useState(false)
  return (
    <Card title={`Continue moving @${saved.oldHandle}?`} sub={<>You started moving this account on {new Date(saved.startedAt).toLocaleString()}. Pick up where you left off.</>}>
      {saved.created && !saved.identityDone && (
        <Notice kind="info">An inactive copy of your account already exists on {here}. Continuing reuses it.</Notice>
      )}
      {saved.identityDone && (
        <Notice kind="warn">
          {adv ? 'Your identity already points to' : 'Your account already points to'} {here}. Continue to finish switching over; starting over isn't
          possible past this point.
        </Notice>
      )}
      <div className="row between">
        {!saved.identityDone ? (
          sure ? (
            <button type="button" className="btn danger" onClick={onReset}>
              Yes, forget this move
            </button>
          ) : (
            <button type="button" className="btn quiet" onClick={() => setSure(true)}>
              Start over with another account
            </button>
          )
        ) : (
          <span />
        )}
        <button type="button" className="btn primary" onClick={onContinue} autoFocus>
          Continue
        </button>
      </div>
    </Card>
  )
}

function SignInStep({
  side,
  saved,
  pds,
  onDone,
  onReset,
}: {
  side: 'old' | 'new'
  saved: Saved
  pds: Pds
  onDone: (password: string, session: { handle: string }) => void
  onReset: () => void
}) {
  const adv = useAdv()
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needCode, setNeedCode] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const host = side === 'old' ? hostOf(saved.oldPds) : here

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    try {
      const out = await pds.login(password, needCode ? code.trim() : undefined)
      onDone(password, out)
    } catch (err) {
      if (err instanceof XrpcError && err.error === 'AuthFactorTokenRequired') {
        setNeedCode(true)
        setError(undefined)
      } else setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card
      title={side === 'old' ? `Sign in to ${host}` : `Sign in to your new account`}
      sub={
        side === 'old' ? (
          <>
            Signing in as <b>@{saved.oldHandle}</b>
            {adv && <span className="mono small"> ({saved.did})</span>}. Your password goes only to {host}; this page keeps it in memory for the move and
            never stores it.
          </>
        ) : (
          <>The account you created here for @{saved.newHandle ?? saved.oldHandle} is waiting. Enter the password you chose for it.</>
        )
      }
    >
      <form onSubmit={submit}>
        {error instanceof XrpcError && error.error === 'AuthenticationRequired' ? (
          <Notice kind="err">
            Wrong password.{' '}
            {side === 'old'
              ? 'Use your main password. App passwords (xxxx-xxxx-xxxx-xxxx) cannot move an account.'
              : 'Use the password you set when creating the account here.'}
          </Notice>
        ) : (
          <Problem error={error} />
        )}
        {needCode && (
          <Notice kind="info">
            {host} emailed you a sign-in code because your account has email two-factor turned on. Enter it below.
          </Notice>
        )}
        <Field label={side === 'old' ? 'Main password' : 'Password'}>
          <input type="password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus={!needCode} />
        </Field>
        {needCode && (
          <Field label="Sign-in code from your email" hint="It looks like ABCDE-12345.">
            <input type="text" name="code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" spellCheck={false} required autoFocus />
          </Field>
        )}
        <div className="row between">
          {!saved.created ? (
            <button type="button" className="btn quiet" onClick={onReset}>
              Use a different account
            </button>
          ) : (
            <span />
          )}
          <button type="submit" className="btn primary" disabled={busy}>
            {busy && <Spinner />}
            Sign in
          </button>
        </div>
      </form>
    </Card>
  )
}

// ---------------------------------------------------------------- 3. checks

type CheckResult = { state: 'ok' | 'warn' | 'bad' | 'wait'; title: string; detail?: ReactNode }

function CheckStep({
  saved,
  describe,
  oldPds,
  update,
  onReset,
}: {
  saved: Saved
  describe: Describe
  oldPds: Pds
  update: (p: Partial<Saved>) => void
  onReset: () => void
}) {
  const adv = useAdv()
  const say = (e: unknown) => (adv ? errText(e) : plainError(e))
  const [checks, setChecks] = useState<Record<string, CheckResult>>({})
  const [tick, setTick] = useState(0)
  const [existing, setExisting] = useState<'none' | 'deactivated' | 'active'>()
  const put = (k: string, c: CheckResult) => setChecks((x) => ({ ...x, [k]: c }))

  useEffect(() => {
    setChecks({})
    const did = saved.did
    // the AppView's counts, through the old server: approximate, and optional
    const profile: Promise<{ postsCount?: number; followsCount?: number } | undefined> = adv
      ? Promise.resolve(undefined)
      : Promise.race([oldPds.call('app.bsky.actor.getProfile', { params: { actor: did } }).catch(() => undefined), sleep(5000).then(() => undefined)])
    put('server', { state: 'ok', title: `${here} is ready`, detail: describe.inviteCodeRequired ? 'New accounts here need an invite code.' : 'Open to new accounts.' })
    put('did', adv ? { state: 'ok', title: 'Your identity can move', detail: <>A did:plc: the PLC directory records which server hosts it.</> } : { state: 'ok', title: 'Your account can move' })
    put('here', { state: 'wait', title: 'Looking for an earlier copy here' })
    call('com.atproto.sync.getRepoStatus', { params: { did } })
      .then((r) => {
        if (r.active) {
          setExisting('active')
          put('here', { state: 'bad', title: 'This account already lives here', detail: <>It's active on {here}. Sign in at <Link to="/account">your account page</Link>.</> })
        } else {
          setExisting('deactivated')
          put('here', { state: 'ok', title: 'An earlier, unfinished copy is here', detail: "We'll reuse it: you'll sign in to it with the password you chose then." })
        }
      })
      .catch((e) => {
        if (e instanceof XrpcError && e.status === 400) {
          setExisting('none')
          put('here', { state: 'ok', title: 'Not on this server yet' })
        } else put('here', { state: 'bad', title: "Couldn't check this server", detail: say(e) })
      })
    put('old', { state: 'wait', title: `Checking your account on ${hostOf(saved.oldPds)}` })
    oldPds
      .call<AccountStatus>('com.atproto.server.checkAccountStatus')
      .then(async (st) => {
        const p = await profile
        if (!st.activated) put('old', { state: 'warn', title: `Your account on ${hostOf(saved.oldPds)} is deactivated`, detail: 'It can still be moved, but it is not live there now.' })
        else put('old', { state: 'ok', title: `Your account on ${hostOf(saved.oldPds)} is active` })
        const big = st.indexedRecords > 500_000 || st.expectedBlobs > 20_000
        put('size', {
          state: big ? 'warn' : 'ok',
          title: adv ? `${fmtNum(st.indexedRecords)} records, ${fmtNum(st.expectedBlobs)} images and videos` : 'Your posts, follows and photos are ready to copy',
          detail: (
            <>
              {!adv && <PreflightCounts posts={p?.postsCount} follows={p?.followsCount} media={st.expectedBlobs} />}
              {big
                ? 'A large account: copying can take a long time. Keep this tab open; if it stops, reload and it picks up where it was.'
                : 'About a minute or two to copy.'}
            </>
          ),
        })
      })
      .catch((e) => put('old', { state: 'bad', title: `Couldn't read your account on ${hostOf(saved.oldPds)}`, detail: say(e) }))
    put('email', { state: 'wait', title: 'Checking your email' })
    oldPds
      .call('com.atproto.server.getSession')
      .then((s) => {
        if (!s.email) put('email', { state: 'bad', title: 'No email on your account', detail: `Moving needs a code emailed by ${hostOf(saved.oldPds)}. Add an email there first.` })
        else {
          update({ email: saved.email ?? s.email })
          put('email', {
            state: s.emailConfirmed === false ? 'warn' : 'ok',
            title: `Codes will go to ${maskEmail(s.email)}`,
            detail: s.emailConfirmed === false ? 'This address is not confirmed; make sure you can receive mail there.' : undefined,
          })
        }
      })
      .catch((e) => put('email', { state: 'bad', title: "Couldn't read your account's email", detail: say(e) }))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick])

  const list = Object.values(checks)
  const pending = list.some((c) => c.state === 'wait')
  const blocked = list.some((c) => c.state === 'bad')
  return (
    <Card
      title={adv ? 'Pre-flight checks' : 'Checking your account'}
      sub={adv ? 'Nothing has been changed anywhere yet. These checks make sure the move can finish.' : "Nothing has changed yet. We're making sure the move can finish."}
    >
      <ul className="mig-checks">
        {list.map((c) => (
          <Checkline key={c.title} state={c.state} title={c.title}>
            {c.detail}
          </Checkline>
        ))}
      </ul>
      <div className="row between">
        <button type="button" className="btn quiet" onClick={onReset}>
          Cancel
        </button>
        <div className="row">
          {blocked && (
            <button type="button" className="btn" onClick={() => setTick((t) => t + 1)}>
              Check again
            </button>
          )}
          <button
            type="button"
            className="btn primary"
            disabled={pending || blocked}
            onClick={() => update({ checkedAt: Date.now(), ...(existing === 'deactivated' ? { created: true, newHandle: saved.newHandle ?? saved.oldHandle } : {}) })}
          >
            Continue
          </button>
        </div>
      </div>
    </Card>
  )
}

function PreflightCounts({ posts, follows, media }: { posts?: number; follows?: number; media: number }) {
  const records = tally({ posts, follows })
  const photos = tally({ media })
  if (!records.length && !photos.length) return null
  return (
    <div className="mig-counts">
      {records.length
        ? `About ${andList(records)}${photos.length ? `, plus ${photos[0]}` : ''}.`
        : `${photos[0]}, plus your posts, likes and follows.`}
    </div>
  )
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

function maskEmail(e: string) {
  const [u, d] = e.split('@')
  return d ? `${u.slice(0, 1)}•••@${d}` : e
}

// ---------------------------------------------------------------- 4. handle

function HandleStep({ saved, describe, update }: { saved: Saved; describe: Describe; update: (p: Partial<Saved>) => void }) {
  const adv = useAdv()
  const domains = describe.availableUserDomains
  const [domain, setDomain] = useState(domains[0] ?? '')
  const provided = saved.oldDomains.some((d) => saved.oldHandle.endsWith(d))
  const custom = !provided && !saved.oldHandle.startsWith('did:') && saved.oldHandle !== 'handle.invalid'
  const [mode, setMode] = useState<'keep' | 'new'>(custom ? 'keep' : 'new')
  const [name, setName] = useState(() => (saved.oldHandle.split('.')[0] || '').replace(/[^a-z0-9-]/gi, '').slice(0, 18).toLowerCase())
  const full = `${name.trim().toLowerCase()}${domain}`
  const [avail, setAvail] = useState<{ handle: string; ok: boolean; suggestions: string[] } | { error: unknown }>()
  const keepCheck = useLoad(
    () =>
      custom
        ? call('com.atproto.identity.resolveHandle', { params: { handle: saved.oldHandle } })
            .then((r) => r.did === saved.did)
            .catch(() => false)
        : Promise.resolve(false),
    [],
  )

  useEffect(() => {
    if (mode !== 'new' || name.trim().length < 3) {
      setAvail(undefined)
      return
    }
    let live = true
    const t = setTimeout(() => {
      call('com.atproto.temp.checkHandleAvailability', { params: { handle: full } })
        .then((r) => {
          if (!live) return
          const ok = String(r.result?.$type ?? '').endsWith('#resultAvailable')
          setAvail({ handle: full, ok, suggestions: (r.result?.suggestions ?? []).map((s: any) => s.handle) })
        })
        .catch((error) => live && setAvail({ error }))
    }, 350)
    return () => {
      live = false
      clearTimeout(t)
    }
  }, [mode, full, name])

  const ready = mode === 'keep' || (avail && 'ok' in avail && avail.ok && avail.handle === full)
  return (
    <Card
      title="Choose your handle"
      sub={
        adv
          ? 'Your handle is the name people see and mention. Your followers and DID stay the same whichever you pick.'
          : 'Your handle is the name people see and mention. Your followers stay with you whichever you pick.'
      }
    >
      {provided && (
        <Notice kind="info">
          <b>@{saved.oldHandle}</b> belongs to {hostOf(saved.oldPds)}, so it stops working when you leave. Pick a new one here; you can switch to your own
          domain any time later.
        </Notice>
      )}
      {custom && (
        <label className="mig-choice">
          <input type="radio" name="handle-mode" checked={mode === 'keep'} onChange={() => setMode('keep')} />
          <div>
            <strong>Keep @{saved.oldHandle}</strong>
            {keepCheck.loading ? (
              <span className="small muted"> Checking it…</span>
            ) : keepCheck.data ? (
              <div className="small muted">
                It points to your account through DNS or your own website, not through {hostOf(saved.oldPds)}, so it keeps working. Nothing to change.
              </div>
            ) : !adv ? (
              <div className="small">
                <Status kind="warn">We couldn't confirm it resolves.</Status> If you set this address up yourself, check your domain's settings; otherwise
                pick a handle here instead.
              </div>
            ) : (
              <div className="small">
                <Status kind="warn">We couldn't confirm it resolves.</Status> Check the <span className="mono">_atproto.{saved.oldHandle}</span> TXT record
                (<span className="mono">did={saved.did}</span>) or <span className="mono">https://{saved.oldHandle}/.well-known/atproto-did</span>. If neither
                is set up, pick a handle here instead.
              </div>
            )}
          </div>
        </label>
      )}
      <label className={custom ? 'mig-choice' : 'mig-choice solo'}>
        {custom && <input type="radio" name="handle-mode" checked={mode === 'new'} onChange={() => setMode('new')} />}
        <div style={{ flex: 1 }}>
          {custom && <strong>Use a handle on {here}</strong>}
          <Field label={custom ? '' : 'New handle'} hint="3 to 18 letters, digits or hyphens.">
            <span className="affix">
              <input
                type="text"
                name="handle"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  setMode('new')
                }}
                autoCapitalize="none"
                spellCheck={false}
                minLength={3}
                maxLength={18}
              />
              <DomainAffix
                domains={domains}
                value={domain}
                placeholder=""
                onChange={(d) => {
                  setDomain(d)
                  setMode('new')
                }}
              />
            </span>
          </Field>
          {mode === 'new' && avail && 'error' in avail && <Problem error={avail.error} />}
          {mode === 'new' && avail && 'ok' in avail && avail.handle === full && (
            <div className="small">
              {avail.ok ? (
                <Status kind="ok">@{full} is available</Status>
              ) : (
                <>
                  <Status kind="bad">@{full} is taken.</Status>
                  {avail.suggestions.length > 0 && (
                    <>
                      {' '}
                      Try{' '}
                      {avail.suggestions.map((s) => (
                        <button key={s} type="button" className="btn quiet mig-sugg" onClick={() => setName(s.slice(0, -domain.length))}>
                          {s}
                        </button>
                      ))}
                    </>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </label>
      <div className="row end">
        <button type="button" className="btn primary" disabled={!ready} onClick={() => update({ newHandle: mode === 'keep' ? saved.oldHandle : full })}>
          Continue
        </button>
      </div>
    </Card>
  )
}

// ---------------------------------------------------------------- 5. create

function CreateStep({
  saved,
  describe,
  oldPds,
  newPds,
  oldPassword,
  invite: urlInvite,
  update,
}: {
  saved: Saved
  describe: Describe
  oldPds: Pds
  newPds: Pds
  oldPassword: string
  invite: string
  update: (p: Partial<Saved>) => void
}) {
  const adv = useAdv()
  const [email, setEmail] = useState(saved.email ?? '')
  const [same, setSame] = useState(!!oldPassword)
  const [password, setPassword] = useState('')
  const [invite, setInvite] = useState(saved.invite ?? urlInvite)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [existsAsk, setExistsAsk] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    const pw = same ? oldPassword : password
    try {
      // fresh each try: service tokens live about a minute
      const { token } = await oldPds.call('com.atproto.server.getServiceAuth', {
        params: { aud: describe.did, lxm: 'com.atproto.server.createAccount' },
      })
      try {
        const out = await call('com.atproto.server.createAccount', {
          auth: `Bearer ${token}`,
          body: { did: saved.did, handle: saved.newHandle, email: email.trim(), password: pw, inviteCode: invite.trim() || undefined },
        })
        newPds.adopt(out)
      } catch (err) {
        // made by an earlier try whose answer never arrived: sign in to it
        if (!(err instanceof XrpcError && /already exists/i.test(err.message))) throw err
        try {
          const out = await newPds.login(pw)
          update({ created: true, newHandle: out.handle, email: email.trim(), invite: undefined })
          return
        } catch (e2) {
          if (e2 instanceof XrpcError && e2.error === 'AuthenticationRequired') {
            setExistsAsk(true)
            return
          }
          throw e2
        }
      }
      update({ created: true, email: email.trim(), invite: undefined })
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  if (existsAsk) {
    return (
      <Card title="Your account here already exists" sub="An earlier attempt created it. Sign in to it with the password you chose then to continue.">
        <SignInInline pds={newPds} onDone={(handle) => update({ created: true, newHandle: handle, email: email.trim(), invite: undefined })} />
      </Card>
    )
  }

  const friendly = createError(error)
  return (
    <Card
      title={`Create @${saved.newHandle} on ${here}`}
      sub={
        adv ? (
          <>This makes an inactive account here with your same DID. Nothing changes on {hostOf(saved.oldPds)} yet.</>
        ) : (
          <>We'll set up your account here. It stays switched off until the last step, and nothing changes on {hostOf(saved.oldPds)} yet.</>
        )
      }
    >
      <form onSubmit={submit}>
        {friendly ? <Notice kind="err">{friendly}</Notice> : <Problem error={error} />}
        <Field label="Email" hint="For password resets and security codes on this server.">
          <input type="email" name="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
        </Field>
        {oldPassword && (
          <label className="check">
            <input type="checkbox" name="same-password" checked={same} onChange={(e) => setSame(e.target.checked)} />
            <span>Use the same password as on {hostOf(saved.oldPds)}</span>
          </label>
        )}
        {!same && (
          <Field label="Password for this server" hint="At least 8 characters.">
            <input
              type="password"
              name="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              minLength={8}
              maxLength={256}
              required
            />
          </Field>
        )}
        {(describe.inviteCodeRequired || invite) && (
          <Field label="Invite code" hint={describe.inviteCodeRequired ? 'This server only takes new accounts with an invite.' : undefined}>
            <input
              type="text"
              name="invite"
              value={invite}
              onChange={(e) => setInvite(e.target.value)}
              autoCapitalize="none"
              spellCheck={false}
              required={describe.inviteCodeRequired}
            />
          </Field>
        )}
        <div className="row end">
          <button type="submit" className="btn primary" disabled={busy}>
            {busy && <Spinner />}
            Create my account here
          </button>
        </div>
      </form>
    </Card>
  )
}

function createError(e: unknown): ReactNode {
  if (!(e instanceof XrpcError)) return null
  if (e.error === 'InvalidInviteCode') return 'That invite code is not valid or has been used up. Ask the operator of this server for another.'
  if (e.error === 'HandleNotAvailable') return 'That handle was just taken. Go back and pick another (reload the page, then change it).'
  if (/^Email already taken/.test(e.message)) return 'Another account here uses that email. Use a different address.'
  if (e.error === 'BadJwtSignature' || e.error === 'BadJwtAudience' || e.error === 'BadJwtLexiconMethod' || e.error === 'JwtExpired')
    return `Your current server's approval didn't check out (${e.error}). Try again.`
  return null
}

function SignInInline({ pds, onDone }: { pds: Pds; onDone: (handle: string) => void }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        setBusy(true)
        setError(undefined)
        try {
          const out = await pds.login(password)
          onDone(out.handle)
        } catch (err) {
          setError(err)
        } finally {
          setBusy(false)
        }
      }}
    >
      <Problem error={error} />
      <Field label="Password">
        <input type="password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus />
      </Field>
      <div className="row end">
        <button className="btn primary" disabled={busy}>
          {busy && <Spinner />}
          Sign in
        </button>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------- 6. copy

type CopyView = {
  repo: { phase?: 'download' | 'upload' | 'verify'; bytes: number; total?: number; records?: [number, number]; found?: RecordCounts }
  blobs: { done: number; total?: number; bytes: number; failed: { cid: string; reason: string }[]; pausedUntil?: number }
  prefs?: number
  error?: unknown
  mismatch?: string
  running: boolean
}

function CopyStep({ saved, oldPds, newPds, update }: { saved: Saved; oldPds: Pds; newPds: Pds; update: (p: Partial<Saved>) => void }) {
  const adv = useAdv()
  const [v, setV] = useState<CopyView>({ repo: { bytes: 0 }, blobs: { done: 0, bytes: 0, failed: [] }, running: false })
  const set = (f: (v: CopyView) => CopyView) => setV((x) => f(x))
  const savedRef = useRef(saved)
  savedRef.current = saved
  const stop = useRef(false)

  const run = useCallback(
    (opts: { acceptMismatch?: boolean; skipFailed?: boolean } = {}) =>
      once(`copy:${saved.did}`, async () => {
        stop.current = false
        set((x) => ({ ...x, running: true, error: undefined, mismatch: undefined }))
        try {
          const s = () => savedRef.current
          if (!s().repoDone) {
            // counting is for show: a CAR it can't read just means no numbers
            let counting: Promise<RecordCounts | undefined> = Promise.resolve(undefined)
            await copyRepo(
              oldPds,
              newPds,
              (phase, bytes, total) => set((x) => ({ ...x, repo: { ...x.repo, phase, bytes, total } })),
              (car) => {
                counting = Promise.all([car.arrayBuffer(), import('./count')])
                  .then(([b, m]) => m.countRecords(new Uint8Array(b)))
                  .catch(() => undefined)
                counting.then((found) => found && set((x) => ({ ...x, repo: { ...x.repo, found } })))
              },
            )
            set((x) => ({ ...x, repo: { ...x.repo, phase: 'verify' } }))
            const [a, b] = await Promise.all([
              oldPds.call<AccountStatus>('com.atproto.server.checkAccountStatus'),
              newPds.call<AccountStatus>('com.atproto.server.checkAccountStatus'),
            ])
            set((x) => ({ ...x, repo: { ...x.repo, records: [a.indexedRecords, b.indexedRecords] } }))
            if (a.indexedRecords !== b.indexedRecords && !opts.acceptMismatch) {
              set((x) => ({ ...x, mismatch: `${hostOf(saved.oldPds)} reports ${fmtNum(a.indexedRecords)} records; the copy here has ${fmtNum(b.indexedRecords)}.` }))
              return
            }
            const found = await counting
            update({ repoDone: true, counts: found && found.total === b.indexedRecords ? found : undefined })
          }
          if (!s().blobsDone) {
            const unavailable = new Set(s().unavailableBlobs ?? [])
            const before = new Set(s().failedBlobs ?? [])
            // "Continue without them": what already failed isn't fetched again
            if (opts.skipFailed) for (const c of before) unavailable.add(c)
            // a blob gets its retries in one pass; later passes are for the rest
            const skip = new Set(unavailable)
            const failedNow = new Map<string, { cid: string; reason: string }>()
            const seen = new Set(before)
            for (let pass = 0; pass < 5 && !stop.current; pass++) {
              const st = await newPds.call<AccountStatus>('com.atproto.server.checkAccountStatus')
              set((x) => ({ ...x, blobs: { ...x.blobs, done: st.importedBlobs, total: st.expectedBlobs } }))
              const r = await copyBlobs(
                oldPds,
                newPds,
                skip,
                (_cid, bytes) => set((x) => ({ ...x, blobs: { ...x.blobs, done: x.blobs.done + 1, bytes: x.blobs.bytes + bytes, pausedUntil: undefined } })),
                () => stop.current,
                (until) => set((x) => ({ ...x, blobs: { ...x.blobs, pausedUntil: until } })),
                {
                  once: before,
                  onFailed: (cid) => {
                    // kept as they happen, so a reload mid-copy doesn't give them the full schedule again
                    if (!seen.has(cid)) {
                      seen.add(cid)
                      update({ failedBlobs: [...seen] })
                    }
                  },
                },
              )
              for (const f of r.failed) {
                failedNow.set(f.cid, f)
                skip.add(f.cid)
              }
              if (r.copied === 0) break
            }
            if (stop.current) return
            const failed = [...failedNow.values()]
            set((x) => ({ ...x, blobs: { ...x.blobs, failed } }))
            update({ failedBlobs: failed.map((f) => f.cid) })
            if (failed.length && !opts.skipFailed) return
            for (const f of failed) unavailable.add(f.cid)
            update({ blobsDone: true, failedBlobs: undefined, unavailableBlobs: unavailable.size ? [...unavailable] : undefined })
          }
          if (!s().prefsDone) {
            const p = await oldPds.call('app.bsky.actor.getPreferences')
            await newPds.call('app.bsky.actor.putPreferences', { body: { preferences: p.preferences ?? [] } })
            set((x) => ({ ...x, prefs: (p.preferences ?? []).length }))
            update({ prefsDone: true })
          }
        } catch (e) {
          set((x) => ({ ...x, error: e }))
        } finally {
          set((x) => ({ ...x, running: false }))
        }
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [saved.did],
  )

  useEffect(() => {
    stop.current = false
    run()
    return () => {
      stop.current = true
    }
  }, [run])

  const r = v.repo
  const copied = saved.counts ? tally(saved.counts) : []
  const found = r.found ? tally(r.found) : []
  const media = (n: number) => (adv ? '' : ` ${noun('media', n)}`)
  return (
    <Card title="Copying your data" sub={<>From {hostOf(saved.oldPds)} to {here}. Your account there keeps working meanwhile. If anything stops, reload: it picks up where it was.</>}>
      <ul className="mig-checks">
        <Checkline
          state={saved.repoDone ? 'ok' : v.mismatch ? 'warn' : v.error && !saved.repoDone ? 'bad' : 'wait'}
          title={adv ? 'Posts, follows, likes and profile (your repository)' : 'Your posts, follows, likes and profile'}
        >
          {saved.repoDone ? (
            adv ? (
              `${r.records ? `${fmtNum(r.records[1])} records copied and checked` : 'Copied'}${copied.length ? ` (${copied.join(', ')})` : ''}.`
            ) : copied.length ? (
              <span className="mig-counts">All {andList(copied)} copied.</span>
            ) : r.records ? (
              'Copied and checked.'
            ) : (
              'Copied.'
            )
          ) : r.phase === 'download' ? (
            <>
              Downloading from {hostOf(saved.oldPds)}: {fmtBytes(r.bytes)}
              {r.total ? ` of ${fmtBytes(r.total)}` : ''}
              <Bar value={r.bytes} total={r.total} label="Repository download" />
            </>
          ) : r.phase === 'upload' ? (
            <>
              {found.length > 0 && !adv && <div className="mig-counts">Copying {andList(found)}.</div>}
              Uploading here: {fmtBytes(r.bytes)} of {fmtBytes(r.total ?? 0)}
              <Bar value={r.bytes} total={r.total} label="Repository upload" />
            </>
          ) : r.phase === 'verify' ? (
            found.length && !adv ? `Checking the copy of ${andList(found)}…` : 'Checking the copy…'
          ) : (
            'Starting…'
          )}
        </Checkline>
        <Checkline
          state={saved.blobsDone ? 'ok' : v.blobs.failed.length && !v.running ? 'warn' : saved.repoDone ? 'wait' : 'wait'}
          title={adv ? 'Images and videos (blobs)' : 'Your photos and videos'}
        >
          {saved.blobsDone ? (
            saved.unavailableBlobs?.length ? (
              `Copied, except ${saved.unavailableBlobs.length} that ${hostOf(saved.oldPds)} couldn't provide.`
            ) : v.blobs.total && !adv ? (
              <span className="mig-counts">All {tally({ media: v.blobs.total })[0]} copied.</span>
            ) : (
              'All copied.'
            )
          ) : !saved.repoDone ? (
            adv ? 'After the repository.' : 'Next.'
          ) : (
            <>
              {fmtNum(v.blobs.done)}
              {v.blobs.total !== undefined ? ` of ${fmtNum(v.blobs.total)}${media(v.blobs.total)}` : media(v.blobs.done)} copied{v.blobs.bytes ? ` (${fmtBytes(v.blobs.bytes)} this session)` : ''}
              <Bar value={v.blobs.done} total={v.blobs.total || undefined} label="Images and videos" />
              {v.blobs.pausedUntil && v.blobs.pausedUntil > Date.now() && (
                <div>
                  A server asked us to slow down (rate limit). Resuming by {new Date(v.blobs.pausedUntil).toLocaleTimeString()}; keep this tab open.
                </div>
              )}
            </>
          )}
        </Checkline>
        <Checkline state={saved.prefsDone ? 'ok' : 'wait'} title="App settings (feeds, muted words, content filters)">
          {saved.prefsDone ? (v.prefs !== undefined ? `${v.prefs} settings copied.` : 'Copied.') : saved.blobsDone ? 'Copying…' : 'Last.'}
        </Checkline>
      </ul>
      {v.mismatch && (
        <Notice kind="warn">
          <p>
            {adv ? (
              <>
                <b>The record counts don't match.</b> {v.mismatch}
              </>
            ) : (
              <b>Some of your posts or likes seem to be missing from the copy.</b>
            )}{' '}
            Retrying usually fixes a copy cut short.
          </p>
          <div className="row">
            <button type="button" className="btn" onClick={() => run()}>
              Copy again
            </button>
            <button type="button" className="btn quiet" onClick={() => run({ acceptMismatch: true })}>
              Continue anyway
            </button>
          </div>
        </Notice>
      )}
      {!v.running && v.blobs.failed.length > 0 && !saved.blobsDone && (
        <Notice kind="warn">
          <p>
            <b>{v.blobs.failed.length} {adv ? "files couldn't be copied." : "photos or videos couldn't be copied."}</b>
            {adv && (
              <>
                {' '}
                The first: <span className="mono">{v.blobs.failed[0].cid}</span> ({v.blobs.failed[0].reason}).
              </>
            )}{' '}
            If {hostOf(saved.oldPds)} no longer has them, they'd be missing here too.
          </p>
          <div className="row">
            <button type="button" className="btn" onClick={() => run()}>
              Retry
            </button>
            <button type="button" className="btn quiet" onClick={() => run({ skipFailed: true })}>
              Continue without them
            </button>
          </div>
        </Notice>
      )}
      {!!v.error && !v.running && (
        <>
          <Problem error={v.error} />
          <div className="row end">
            <button type="button" className="btn primary" onClick={() => run()}>
              Retry
            </button>
          </div>
        </>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- 7. backup

const pdsSource = (pds: Pds, handle: string): BackupSource => ({ base: pds.base, did: pds.did, handle, call: (nsid, o) => pds.call(nsid, o) })

/** Optional, and offered once: the last moment the old server's copy is
 * the account's live one. Taken from there, not from the copy here. */
function BackupStep({ saved, oldPds, update }: { saved: Saved; oldPds: Pds; update: (p: Partial<Saved>) => void }) {
  const adv = useAdv()
  const old = hostOf(saved.oldPds)
  const [done, setDone] = useState(false)
  const source = useMemo(() => pdsSource(oldPds, saved.oldHandle), [oldPds, saved.oldHandle])
  return (
    <Card
      title={adv ? 'Back up before the switch' : 'Save a copy of your account'}
      sub={
        adv ? (
          <>
            Optional. Everything is copied here; this is the last chance to keep what {old} holds while it is still your live server. One ZIP:{' '}
            <span className="mono">repo.car</span>, every blob (sha-256 checked against its CID), preferences, your DID document and PLC audit log, and a
            README on restoring anywhere. No passwords or session tokens.
          </>
        ) : (
          <>
            Optional. Before the switch, you can keep a copy of your whole account from {old} on this device: posts, follows, likes, photos and videos,
            and settings, in one .zip file. Everything has already been copied here either way.
          </>
        )
      }
    >
      {adv && (
        <p className="small muted">
          {canStreamToDisk()
            ? 'This browser writes the ZIP straight to the file you pick, so size is no concern.'
            : 'This browser assembles the ZIP in memory, then saves it to your downloads.'}
        </p>
      )}
      <BackupBox
        source={source}
        simple={!adv}
        primary={!done}
        onSaved={() => setDone(true)}
        leading={
          done ? undefined : (
            <button type="button" className="btn" name="skip-backup" onClick={() => update({ backup: 'skipped' })}>
              Skip
            </button>
          )
        }
        trailing={
          done ? (
            <button type="button" className="btn primary" onClick={() => update({ backup: 'saved' })}>
              Continue
            </button>
          ) : undefined
        }
      />
    </Card>
  )
}

// ---------------------------------------------------------------- 8. identity

/** A recovery key generated during this move, for the welcome screen's
 * backup. Memory only: gone with the tab, never in storage. */
let madeKey: { did: string; privateHex: string; didKey: string } | undefined

type Recommended = {
  alsoKnownAs: string[]
  verificationMethods: { atproto: string }
  rotationKeys: string[]
  services: { atproto_pds: { type: string; endpoint: string } }
}

function IdentityStep({ saved, oldPds, newPds, update }: { saved: Saved; oldPds: Pds; newPds: Pds; update: (p: Partial<Saved>) => void }) {
  const adv = useAdv()
  const rec = useLoad<Recommended>(() => newPds.call('com.atproto.identity.getRecommendedDidCredentials'), [])
  const doc = useLoad<DidDoc>(() => call('com.atproto.identity.resolveDid', { params: { did: saved.did } }).then((r) => r.didDoc), [])
  const [token, setToken] = useState('')
  const [understood, setUnderstood] = useState(false)
  const [busy, setBusy] = useState<'' | 'request' | 'move'>('')
  const [error, setError] = useState<unknown>()
  const [sentNow, setSentNow] = useState(false)
  const [keyOpen, setKeyOpen] = useState(false)
  const [userKey, setUserKey] = useState<RecoveryKeyChoice>({ status: 'empty' })
  const pending = signedOp(saved.did)
  const requested = !!saved.plcRequestedAt
  useEffect(() => {
    // the move may have landed in a tab that closed before it could note it
    newPds
      .call<AccountStatus>('com.atproto.server.checkAccountStatus')
      .then((st) => st.validDid && update({ identityDone: true }))
      .catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // only an open advanced section counts: simple mode never adds a key
  const ownKey = adv && keyOpen && userKey.status === 'ready' ? userKey.didKey : undefined
  const keyUnfinished = adv && keyOpen && userKey.status === 'incomplete'
  const r = rec.data
  // highest priority first: the user's key can undo the server's ops for 72 h
  const rotationKeys = r ? [...(ownKey ? [ownKey] : []), ...r.rotationKeys.filter((k) => k !== ownKey)] : []
  const signedKeys = (pending as { rotationKeys?: string[] } | undefined)?.rotationKeys
  const shownKeys = signedKeys ?? rotationKeys

  const request = async () => {
    setBusy('request')
    setError(undefined)
    try {
      await oldPds.call('com.atproto.identity.requestPlcOperationSignature', { method: 'POST' })
      update({ plcRequestedAt: Date.now() })
      setSentNow(true)
    } catch (e) {
      setError(e)
    } finally {
      setBusy('')
    }
  }

  const move = async (e?: FormEvent) => {
    e?.preventDefault()
    setBusy('move')
    setError(undefined)
    try {
      let op = signedOp(saved.did)
      if (!op) {
        const out = await oldPds.call('com.atproto.identity.signPlcOperation', {
          body: { token: token.trim(), rotationKeys, alsoKnownAs: r!.alsoKnownAs, verificationMethods: r!.verificationMethods, services: r!.services },
        })
        op = out.operation
        keepSignedOp(saved.did, op)
      }
      await newPds.call('com.atproto.identity.submitPlcOperation', { body: { operation: op } })
      keepSignedOp(saved.did, undefined)
      if (ownKey && userKey.status === 'ready' && userKey.privateHex && userKey.didKey === ownKey) {
        madeKey = { did: saved.did, privateHex: userKey.privateHex, didKey: ownKey }
      }
      update({ identityDone: true })
    } catch (err) {
      setError(err)
    } finally {
      setBusy('')
    }
  }

  const d = doc.data
  const old = hostOf(saved.oldPds)
  const tokenError = error instanceof XrpcError && (error.error === 'InvalidToken' || error.error === 'ExpiredToken')
  const moveLabel = adv ? 'Move my identity' : 'Move my account'
  return (
    <Card
      title={adv ? 'Move your identity' : 'Confirm the move'}
      sub={
        adv ? (
          <>
            Your data is all here. The last step tells the PLC directory that <b>{here}</b> now hosts <span className="mono">{saved.did}</span>. Apps and
            relays follow that record, so this is the switch-over moment.
          </>
        ) : (
          <>
            Your posts and photos are all here. This last step points your account at <b>{here}</b>: it's the moment the switch happens.
          </>
        )
      }
    >
      <Problem error={rec.error || doc.error} />
      {adv && r && (
        <table className="data mig-diff">
          <thead>
            <tr>
              <th />
              <th>Now</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>Hosting server</th>
              <td className="mono">{d ? pdsOf(d) : old}</td>
              <td className="mono">{r.services.atproto_pds.endpoint}</td>
            </tr>
            <tr>
              <th>Handle</th>
              <td className="mono">{d?.alsoKnownAs?.join(', ') ?? `at://${saved.oldHandle}`}</td>
              <td className="mono">{r.alsoKnownAs.join(', ')}</td>
            </tr>
            <tr>
              <th>Signing key</th>
              <td className="mono" title={d && signingKeyOf(d)}>
                {shortKey(d && signingKeyOf(d))}
              </td>
              <td className="mono" title={r.verificationMethods.atproto}>
                {shortKey(r.verificationMethods.atproto)}
              </td>
            </tr>
            <tr>
              <th>Rotation keys</th>
              <td className="muted">{old}'s</td>
              <td className="mono mig-rotation">
                {shownKeys.map((k) => (
                  <div key={k} title={k}>
                    {shortKey(k)}
                    {k === ownKey && <span className="mig-yours">yours</span>}
                  </div>
                ))}
              </td>
            </tr>
          </tbody>
        </table>
      )}
      {!adv && r && (
        <p>
          Your account will be hosted at <b>{here}</b>
          {r.alsoKnownAs[0] ? <>, as @{r.alsoKnownAs[0].replace(/^at:\/\//, '')}</> : null}.
        </p>
      )}
      <Notice kind="warn">
        {adv ? (
          <p>
            <b>This is the point of no return for this page.</b> Once the directory accepts the change, {here} controls your identity: {old} can't move it
            back for you. Rotation keys you added yourself are replaced by the ones above
            {ownKey ? ' (your new recovery key included)' : ' (add one below, or later from your account page here)'}. Going back later means moving again,
            from {here}.
          </p>
        ) : (
          <p>
            <b>After this step your account lives here.</b> You can still sign in to {old} for a while, but it won't be in use. Moving back later means
            moving again, from {here}.
          </p>
        )}
      </Notice>
      {adv && !pending && (
        <details className="mig-adv" open={keyOpen} onToggle={(e) => setKeyOpen((e.target as HTMLDetailsElement).open)}>
          <summary>Advanced: add your own recovery key</summary>
          <p className="small">
            <RecoveryKeyExplainer server={here} />
          </p>
          <RecoveryKeyPicker onChange={setUserKey} />
          {ownKey && (
            <Notice kind="ok">
              <span className="mono small">{shortKey(ownKey)}</span> goes first in your rotation keys, ahead of {here}'s.
            </Notice>
          )}
        </details>
      )}
      {pending ? (
        <>
          <Notice kind="info">Your current server already signed the change. It just needs to reach {adv ? 'the directory' : 'the finish line'}.</Notice>
          <Problem error={error} />
          <div className="row end">
            <button type="button" className="btn primary" disabled={!!busy} onClick={() => move()}>
              {busy === 'move' && <Spinner />}
              {adv ? 'Finish moving my identity' : 'Finish moving my account'}
            </button>
          </div>
        </>
      ) : !requested ? (
        <>
          <p>
            {old} has to approve the change: it emails a confirmation code to {saved.email ? maskEmail(saved.email) : 'your account email'}.
          </p>
          <Problem error={error} />
          <div className="row end">
            <button type="button" className="btn primary" disabled={!!busy || !r} onClick={request}>
              {busy === 'request' && <Spinner />}
              Email me a confirmation code
            </button>
          </div>
        </>
      ) : (
        <form onSubmit={move}>
          {sentNow && <Notice kind="ok">Code sent. Check your inbox (and spam) for mail from {old}.</Notice>}
          {tokenError ? (
            <Notice kind="err">
              {(error as XrpcError).error === 'ExpiredToken' ? 'That code has expired.' : "That code isn't right."} Check it, or send a new code.
            </Notice>
          ) : (
            <Problem error={error} />
          )}
          <Field
            label="Confirmation code"
            hint={
              adv
                ? 'From the email titled something like “PLC Update Operation Requested”. It looks like ABCDE-12345.'
                : `From the email ${old} just sent you. It looks like ABCDE-12345.`
            }
          >
            <input type="text" name="plc-token" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="one-time-code" spellCheck={false} required />
          </Field>
          <label className="check">
            <input type="checkbox" name="understood" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />
            <span>{adv ? <>I understand: after this, {here} hosts my account and my identity.</> : <>I understand: after this, my account lives on {here}.</>}</span>
          </label>
          {keyUnfinished && (
            <Notice kind="warn">Finish adding your recovery key above (or close that section) before moving.</Notice>
          )}
          <div className="row between">
            <button type="button" className="btn quiet" disabled={!!busy} onClick={request}>
              {busy === 'request' && <Spinner />}
              Send a new code
            </button>
            <button type="submit" className="btn primary" disabled={!!busy || !understood || !r || keyUnfinished}>
              {busy === 'move' && <Spinner />}
              {moveLabel}
            </button>
          </div>
        </form>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- 9. finish

function FinishStep({
  saved,
  oldPds,
  newPds,
  update,
  oauthError,
}: {
  saved: Saved
  oldPds: Pds
  newPds: Pds
  update: (p: Partial<Saved>) => void
  oauthError?: unknown
}) {
  const [error, setError] = useState<unknown>()
  const [running, setRunning] = useState(false)
  const savedRef = useRef(saved)
  savedRef.current = saved

  const run = useCallback(
    () =>
      once(`finish:${saved.did}`, async () => {
        setRunning(true)
        setError(undefined)
        try {
          if (!savedRef.current.activated) {
            await newPds.call('com.atproto.server.activateAccount', { method: 'POST' })
            update({ activated: true })
          }
          // space repos import only once the account is live here, and are
          // read there before that account goes offline
          if (!savedRef.current.spaces) return
          if (!savedRef.current.oldDeactivated) {
            await oldPds.call('com.atproto.server.deactivateAccount', { body: {} })
            update({ oldDeactivated: true, finishedAt: Date.now() })
          }
        } catch (e) {
          setError(e)
        } finally {
          setRunning(false)
        }
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [saved.did],
  )
  useEffect(() => {
    run()
  }, [run, saved.spaces])

  const spacesLine = saved.spaces === 'none' ? null : (
    <Checkline
      state={saved.spaces === 'done' ? (saved.spaceMoves?.some((m) => m.state === 'failed') ? 'warn' : 'ok') : saved.spaces === 'skipped' ? 'warn' : 'wait'}
      title="Copy your Spaces"
    >
      {saved.spaces === 'skipped'
        ? `Not copied: they stay at ${hostOf(saved.oldPds)}.`
        : saved.spaces === 'done'
          ? spacesSummary(saved.spaceMoves ?? [])
          : saved.activated
            ? 'Private data you wrote in Spaces, copied from your old server.'
            : undefined}
    </Checkline>
  )

  return (
    <Card title="Switching over" sub={<>Turning your account on here, then off at {hostOf(saved.oldPds)}.</>}>
      <ul className="mig-checks">
        <Checkline state={saved.activated ? 'ok' : error ? 'bad' : 'wait'} title={`Activate your account on ${here}`}>
          {saved.activated ? 'Live: the network now reads your posts from here.' : undefined}
        </Checkline>
        {spacesLine}
        <Checkline state={saved.oldDeactivated ? 'ok' : error && saved.activated && saved.spaces ? 'bad' : 'wait'} title={`Deactivate your old account on ${hostOf(saved.oldPds)}`}>
          Deactivated, not deleted: it stays there, offline, as a fallback.
        </Checkline>
      </ul>
      {saved.activated && !saved.spaces && <SpacesBox saved={saved} update={update} oauthError={oauthError} />}
      {!!error && !running && (
        <>
          <Problem error={error} />
          {saved.activated && (
            <Notice kind="info">
              Your account is already live here. The old copy is still switched on at {hostOf(saved.oldPds)}; retry, or deactivate it later from there.
            </Notice>
          )}
          <div className="row end">
            {saved.activated && saved.spaces && (
              <button type="button" className="btn quiet" onClick={() => update({ oldDeactivated: true, finishedAt: Date.now() })}>
                Skip, I'll do it later
              </button>
            )}
            <button type="button" className="btn primary" onClick={() => run()}>
              Retry
            </button>
          </div>
        </>
      )}
    </Card>
  )
}

function spacesSummary(moves: SpaceMove[]): string {
  const moved = moves.filter((m) => m.state === 'moved').length
  const failed = moves.filter((m) => m.state === 'failed').length
  if (!moved && !failed) return 'Nothing to copy.'
  return failed ? `${moved} of ${moved + failed} copied; ${failed} stayed behind.` : `All ${moved} copied.`
}

// ---------------------------------------------------------------- spaces

type SpacesPhase =
  | { at: 'probe' }
  | { at: 'sign-in-old' }
  | { at: 'plan' }
  | { at: 'sign-in-new'; plans: SpacePlan[] }
  | { at: 'copy'; plans: SpacePlan[] }
  | { at: 'result' }

/** Lists the space repos at the old server and imports each here, with an
 * OAuth sign-in on each side (space data never rides a password session). */
function SpacesBox({ saved, update, oauthError }: { saved: Saved; update: (p: Partial<Saved>) => void; oauthError?: unknown }) {
  const adv = useAdv()
  const oldHost = hostOf(saved.oldPds)
  const [phase, setPhase] = useState<SpacesPhase>({ at: 'probe' })
  const [error, setError] = useState<unknown>(oauthError)
  const [busy, setBusy] = useState(false)
  const [moves, setMoves] = useState<SpaceMove[]>(saved.spaceMoves ?? [])
  const [current, setCurrent] = useState<{ uri: string; blobs: number; total: number } | null>(null)
  const [pausedUntil, setPausedUntil] = useState(0)
  const client = clientInfo()
  const savedRef = useRef(saved)
  savedRef.current = saved

  const sessions = async () => ({
    old: await OAuthSession.load('old', saved.did, saved.oldPds),
    here: await OAuthSession.load('new', saved.did, location.origin),
  })

  const step = useCallback(
    () =>
      once(`spaces:${saved.did}`, async () => {
        try {
          const [hereOn, thereOn] = await Promise.all([servesSpaces(''), servesSpaces(saved.oldPds)])
          if (!hereOn || !thereOn) {
            update({ spaces: 'none' })
            return
          }
          const { old, here: mine } = await sessions()
          const narrowed = new Error("That sign-in didn't allow everything the copy needs. Sign in again and leave every permission ticked.")
          if (!old || !old.grants(OLD_SCOPE)) {
            if (old) setError(narrowed)
            return setPhase({ at: 'sign-in-old' })
          }
          setPhase({ at: 'plan' })
          const plans = await plan(old, setPausedUntil)
          if (!plans.length) {
            await forgetAll(['old', 'new'])
            update({ spaces: 'none', spaceMoves: [] })
            return
          }
          const scope = plans.some((p) => p.blobs.length) ? `${NEW_SCOPE} ${BLOB_SCOPE}` : NEW_SCOPE
          if (!mine || !mine.grants(scope)) {
            if (mine) setError(narrowed)
            return setPhase({ at: 'sign-in-new', plans })
          }
          setPhase({ at: 'copy', plans })
          let done = (savedRef.current.spaceMoves ?? []).filter((m) => m.state !== 'failed')
          for (const p of plans) {
            if (done.some((m) => m.uri === p.uri)) continue
            setCurrent({ uri: p.uri, blobs: 0, total: p.blobs.length })
            let m: SpaceMove
            try {
              m = await copySpace(old, mine, p, setPausedUntil, (n) => setCurrent({ uri: p.uri, blobs: n, total: p.blobs.length }))
            } catch (e) {
              m = { uri: p.uri, state: 'failed', reason: reasonOf(e) }
            }
            done = [...done.filter((x) => x.uri !== p.uri), m]
            setMoves(done)
            update({ spaceMoves: done })
          }
          setCurrent(null)
          setPhase({ at: 'result' })
        } catch (e) {
          setError(e)
          setPhase((ph) => (ph.at === 'plan' || ph.at === 'copy' ? { at: 'result' } : ph))
        }
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [saved.did],
  )
  useEffect(() => {
    step()
  }, [step])

  const signIn = async (name: 'old' | 'new', pds: string, scope: string) => {
    setBusy(true)
    setError(undefined)
    try {
      await beginSignIn({ name, pds, did: saved.did, scope })
    } catch (e) {
      setError(e)
      setBusy(false)
    }
  }
  const finish = async (state: 'done' | 'skipped') => {
    setBusy(true)
    await forgetAll(['old', 'new'])
    update({ spaces: state, spaceMoves: state === 'done' ? moves : saved.spaceMoves })
  }
  const retryFailed = () => {
    const kept = moves.filter((m) => m.state !== 'failed')
    setMoves(kept)
    update({ spaceMoves: kept })
    setError(undefined)
    step()
  }

  const skip = (
    <button type="button" className="btn quiet" name="skip-spaces" disabled={busy} onClick={() => finish('skipped')}>
      Skip: leave them at {oldHost}
    </button>
  )
  const failed = moves.filter((m) => m.state === 'failed')
  const moved = moves.filter((m) => m.state === 'moved')
  const paused = pausedUntil > Date.now()

  return (
    <div className="mig-spaces">
      {!!error && <Problem error={error} />}
      {phase.at === 'probe' || phase.at === 'plan' ? (
        <p className="small muted">
          <Spinner /> {phase.at === 'probe' ? 'Checking for Spaces…' : `Listing your Spaces at ${oldHost}…`}
        </p>
      ) : phase.at === 'sign-in-old' ? (
        <>
          <p>
            Private data you wrote in Spaces only moves with a separate sign-in: first at <b>{oldHost}</b>, to read it, then here, to bring it in.
            {adv && <> OAuth only, as all space data: the scope asks to read your own space repos there ({OLD_SCOPE.split(' ').slice(1).join(' ')}).</>}
          </p>
          {!client && <Notice kind="warn">Signing in with OAuth needs this page on https (or http://127.0.0.1 for development).</Notice>}
          <div className="row between">
            {skip}
            <button type="button" className="btn primary" name="spaces-sign-in-old" disabled={busy || !client} onClick={() => signIn('old', saved.oldPds, OLD_SCOPE)}>
              {busy && <Spinner />}
              Sign in at {oldHost}
            </button>
          </div>
        </>
      ) : phase.at === 'sign-in-new' ? (
        <>
          <p>
            Found {phase.plans.length === 1 ? '1 space' : `${phase.plans.length} spaces`} at {oldHost}. Now sign in here, at <b>{here}</b>, to bring{' '}
            {phase.plans.length === 1 ? 'it' : 'them'} in.
            {adv && <> The scope imports space repos{phase.plans.some((p) => p.blobs.length) ? ' and uploads the blobs they name' : ''}.</>}
          </p>
          <div className="row between">
            {skip}
            <button
              type="button"
              className="btn primary"
              name="spaces-sign-in-new"
              disabled={busy}
              onClick={() => signIn('new', location.origin, phase.plans.some((p) => p.blobs.length) ? `${NEW_SCOPE} ${BLOB_SCOPE}` : NEW_SCOPE)}
            >
              {busy && <Spinner />}
              Sign in at {here}
            </button>
          </div>
        </>
      ) : (
        <>
          {phase.at === 'copy' && current && (
            <>
              <p className="small">
                <Spinner /> Copying {spaceName(current.uri, adv)}
                {current.total > 0 && ` (${current.blobs} of ${current.total} ${adv ? 'blobs' : 'files'})`}…{paused && ' Paused: the server asked us to slow down.'}
              </p>
              <Bar value={moves.length} total={phase.plans.length} label="Spaces copied" />
            </>
          )}
          {moves.length > 0 && (
            <ul className="mig-space-list">
              {moves.map((m) => (
                <li key={m.uri} className={m.state}>
                  <span className="icon">{m.state === 'failed' ? <I.Alert /> : <I.Check />}</span>
                  <span>
                    {spaceName(m.uri, adv)}:{' '}
                    {m.state === 'moved'
                      ? `copied${m.records !== undefined ? ` (${fmtNum(m.records)} ${m.records === 1 ? 'record' : 'records'}${m.blobs ? `, ${m.blobs} ${adv ? (m.blobs === 1 ? 'blob' : 'blobs') : m.blobs === 1 ? 'file' : 'files'}` : ''})` : ''}`
                      : m.state === 'empty'
                        ? 'nothing of yours in it'
                        : `not copied: ${m.reason}`}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {phase.at === 'result' && (
            <>
              {failed.length > 0 ? (
                <Notice kind="warn">
                  {failed.length === 1 ? '1 space' : `${failed.length} spaces`} didn't copy. Retry, or go on without {failed.length === 1 ? 'it' : 'them'}: {failed.length === 1 ? 'it stays' : 'they stay'} at {oldHost}, which goes offline next.
                </Notice>
              ) : (
                <Notice kind="ok">
                  {moved.length ? `All ${moved.length === 1 ? 'of your Spaces' : `${moved.length} Spaces`} copied.` : 'Nothing to copy.'}
                </Notice>
              )}
              <div className="row between">
                {failed.length > 0 ? (
                  <button type="button" className="btn quiet" name="spaces-continue" disabled={busy} onClick={() => finish('done')}>
                    Continue without them
                  </button>
                ) : (
                  <span />
                )}
                {failed.length > 0 || error ? (
                  <button type="button" className="btn primary" name="spaces-retry" disabled={busy} onClick={retryFailed}>
                    Retry
                  </button>
                ) : (
                  <button type="button" className="btn primary" name="spaces-continue" disabled={busy} onClick={() => finish('done')}>
                    Continue
                  </button>
                )}
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}

function spaceName(uri: string, adv: boolean): string {
  const { type, skey } = spaceLabel(uri)
  return adv ? uri : `${type}${skey && skey !== 'self' ? ` (${skey})` : ''}`
}

// ---------------------------------------------------------------- done

function DoneStep({ saved, newPds, onReset }: { saved: Saved; newPds: Pds; onReset: () => void }) {
  const adv = useAdv()
  const st = useLoad<AccountStatus | null>(() => (newPds.tokens ? newPds.call('com.atproto.server.checkAccountStatus') : Promise.resolve(null)), [])
  const open = () => {
    if (newPds.tokens) setSession({ did: saved.did, handle: saved.newHandle ?? '', ...newPds.tokens })
    onReset()
    navigate('/account')
  }
  return (
    <Card
      title="Welcome to your new home"
      sub={
        <>
          @{saved.newHandle} now lives on {here}. Your followers and posts came with you{adv ? ', and so did your DID' : ''}.
        </>
      }
    >
      {st.data && !adv && saved.counts && (
        <div className="tiles mig-counts">
          {(['posts', 'likes', 'follows', 'reposts'] as const)
            .filter((k) => k !== 'reposts' || saved.counts![k] > 0)
            .map((k) => (
              <div className="tile" key={k}>
                <div className="v">{fmtNum(saved.counts![k])}</div>
                <div className="k">{noun(k, saved.counts![k])}</div>
              </div>
            ))}
          <div className="tile">
            <div className="v">
              {fmtNum(st.data.importedBlobs)}
              {st.data.importedBlobs !== st.data.expectedBlobs && <small>/ {fmtNum(st.data.expectedBlobs)}</small>}
            </div>
            <div className="k">{noun('media', st.data.importedBlobs)}</div>
          </div>
          <div className="tile">
            <div className="v">{st.data.activated && st.data.validDid ? <Status kind="ok">Live</Status> : <Status kind="warn">Check</Status>}</div>
            <div className="k">status</div>
          </div>
        </div>
      )}
      {st.data && (adv || !saved.counts) && (
        <div className="tiles">
          <div className="tile">
            <div className="v">{fmtNum(st.data.indexedRecords)}</div>
            <div className="k">{adv ? 'records' : 'posts, likes and follows'}</div>
          </div>
          <div className="tile">
            <div className="v">
              {fmtNum(st.data.importedBlobs)}
              <small>/ {fmtNum(st.data.expectedBlobs)}</small>
            </div>
            <div className="k">images and videos</div>
          </div>
          <div className="tile">
            <div className="v">{st.data.activated && st.data.validDid ? <Status kind="ok">Live</Status> : <Status kind="warn">Check</Status>}</div>
            <div className="k">status</div>
          </div>
        </div>
      )}
      <ol className="mig-next">
        <li>
          <strong>Sign out of the Bluesky app, then sign back in.</strong>
          On the sign-in screen choose <b>Hosting provider</b> → <b>Custom</b>, and enter <CopyText text={location.origin} />. Use @{saved.newHandle} and the
          password you set here.
        </li>
        <li>
          <strong>Check that it worked.</strong>
          Post something; it should show up for your followers within a minute. Apps can take a few minutes to notice the move.
        </li>
        {!!saved.spaceMoves?.some((m) => m.state === 'failed') && (
          <li>
            <strong>Some of your Spaces stayed behind.</strong>
            {saved.spaceMoves.filter((m) => m.state === 'failed').length} didn't copy. They are still in your old account at {hostOf(saved.oldPds)}, which
            is now deactivated, not deleted.
          </li>
        )}
        <li>
          <strong>Keep your old account for now.</strong>
          It is deactivated at {hostOf(saved.oldPds)}, not deleted. Once you're happy here, you can delete it there.
        </li>
        <li>
          <strong>Set up two-factor sign-in again.</strong>
          Passkeys and authenticator apps belong to the server they were set up on, so none came with you. Add them under <b>Security</b> in your account
          settings here.
        </li>
      </ol>
      {newPds.tokens && (
        <details className="mig-adv mig-backup">
          <summary>{adv ? 'Download a backup from here' : 'Save a copy of your account'}</summary>
          <p className="small">
            {adv
              ? `The same ZIP as before the switch, read from ${here}: repo, blobs, preferences, DID document and PLC audit log.`
              : `One .zip file with your posts, follows, likes, photos and videos, and settings, as they are now on ${here}.`}
          </p>
          <BackupBox
            source={pdsSource(newPds, saved.newHandle ?? saved.oldHandle)}
            simple={!adv}
            primary={false}
            recoveryKey={adv && madeKey?.did === saved.did ? madeKey : undefined}
          />
        </details>
      )}
      <div className="row between">
        <button type="button" className="btn quiet" onClick={onReset}>
          Move another account
        </button>
        <button type="button" className="btn primary" onClick={open}>
          Open your account
        </button>
      </div>
    </Card>
  )
}
