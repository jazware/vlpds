import { useEffect, useRef, useState, type FormEvent, type JSX } from 'react'
import { ErrorNotice, Field, Loading, Notice, Spinner, Topbar } from '../../components/ui'
import { useLoad, useSession } from '../../lib/hooks'
import { Link, match, navigate, syncRoute, useSearch } from '../../lib/router'
import { acall, call, setSession, signOut, XrpcError, errText } from '../../lib/xrpc'
import { serverRunsSpaces } from '../../lib/backup'
import { ACCOUNT_CALLBACK_PATH } from '../../lib/oauth'
import { disconnect, finishCallback, holdsSession } from '../../lib/spaces'
import { SpacesHome, SpaceView } from './Spaces'
import { cancelled, conditionalAvailable, didOfUserHandle, getPasskey, ipHost, passkeysHere, rpIdHere, type AssertionJson } from '../../lib/webauthn'
import { Overview } from './Overview'
import { Identity } from './Identity'
import { Security } from './Security'
import { Collections, Records, RecordView } from './Repo'
import { Blobs } from './Blobs'
import { Export, Preferences } from './Data'
import { Danger } from './Danger'
import { SignUp } from './SignUp'
import { ProviderSignIn, ProviderSignup } from './Providers'
import { finishPendingReturn } from './Providers'
import { redeem } from '../../lib/auth'

const NAV = [
  { to: '/account', label: 'Overview' },
  { to: '/account/identity', label: 'Handle and email' },
  { to: '/account/security', label: 'Security' },
  { to: '/account/repo', label: 'Repository' },
  { to: '/account/blobs', label: 'Media' },
  { to: '/account/spaces', label: 'Spaces', spaces: true },
  { to: '/account/export', label: 'Export' },
  { to: '/account/preferences', label: 'Preferences' },
]

/** Back from the Spaces section's OAuth sign-in: redeem the code, then show where it started. */
function SpacesCallback() {
  useEffect(() => {
    void finishCallback().then(syncRoute)
  }, [])
  return <Loading />
}

export function AccountApp({ path }: { path: string }) {
  const s = useSession()
  const p = path.replace(/\/+$/, '') || '/account'
  // A provider that redirects leaves a proved identity for the sign-up page.
  const params = new URLSearchParams(location.search)
  const signupTxn = params.get('auth') === 'signup' ? params.get('t') : null
  // A provider round trip can return here: redeem a finished sign-in, or
  // finish the link or confirmation the browser left for.
  useEffect(() => {
    const q = new URLSearchParams(location.search)
    const auth = q.get('auth')
    if (!auth) return
    const clean = () => history.replaceState(null, '', location.pathname)
    if (auth === 'complete') {
      void redeem()
        .then((session) => {
          if (session) setSession(session)
          clean()
        })
        .catch(clean)
      return
    }
    // The sign-up page needs its transaction id, so leave the URL alone for it.
    if (auth === 'signup') return
    if (auth === 'pending') {
      const t = q.get('t')
      const step = q.get('step')
      if (t && (step === 'link' || step === 'reauth')) {
        void finishPendingReturn(t, step, s?.accessJwt ?? '').catch(() => {})
      }
      clean()
      navigate('/account/security', { replace: true })
      return
    }
    clean()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  // the Spaces section's OAuth session lives only while the section is open
  useEffect(() => {
    if (p !== ACCOUNT_CALLBACK_PATH && !p.startsWith('/account/spaces') && holdsSession()) void disconnect()
  }, [p])
  if (p === ACCOUNT_CALLBACK_PATH) return <SpacesCallback />
  if (p === '/account/reset') return <PasswordReset />
  if (p === '/account/signup' && !s) return <SignUp />
  if (signupTxn && !s) return <ProviderSignup txn={signupTxn} />
  if (!s) return <SignIn />
  return <SignedIn p={p} />
}

function SignedIn({ p }: { p: string }) {
  const s = useSession()!
  const spaces = useLoad(() => serverRunsSpaces(acall), [s.did]).data
  let page: JSX.Element
  let m: Record<string, string> | null
  if (p === '/account' || p === '/account/signup') page = <Overview />
  else if (p === '/account/identity') page = <Identity />
  else if (p === '/account/security') page = <Security />
  else if (p === '/account/repo') page = <Collections />
  else if ((m = match('/account/repo/:collection', p))) page = <Records collection={m.collection} />
  else if ((m = match('/account/repo/:collection/:rkey', p))) page = <RecordView collection={m.collection} rkey={m.rkey} />
  else if (p === '/account/blobs') page = <Blobs />
  else if (p.startsWith('/account/spaces') && spaces === undefined) page = <Loading />
  else if (p.startsWith('/account/spaces') && !spaces) page = <Notice kind="warn">This server doesn't run Spaces.</Notice>
  else if (p === '/account/spaces') page = <SpacesHome />
  else if ((m = match('/account/spaces/:authority/:type/:skey', p))) page = <SpaceView authority={m.authority} type={m.type} skey={m.skey} />
  else if (p === '/account/export') page = <Export />
  else if (p === '/account/preferences') page = <Preferences />
  else if (p === '/account/danger') page = <Danger />
  else page = <Notice kind="warn">There is no page at {p}.</Notice>

  const current = (to: string) => (to === '/account' ? p === '/account' : p === to || p.startsWith(`${to}/`))
  return (
    <>
      <Topbar where="Account">
        <button type="button" className="btn sm" onClick={() => disconnect().then(signOut).then(() => navigate('/account'))}>
          Sign out
        </button>
      </Topbar>
      <div className="app">
        <aside className="sidenav">
          <div className="who">
            <strong>@{s.handle}</strong>
            <span className="mono">{s.did}</span>
          </div>
          <nav aria-label="Account">
            {NAV.filter((n) => !n.spaces || spaces).map((n) => (
              <Link key={n.to} to={n.to} aria-current={current(n.to) ? 'page' : undefined}>
                {n.label}
              </Link>
            ))}
            <Link to="/account/danger" className="danger-link" aria-current={current('/account/danger') ? 'page' : undefined}>
              Deactivate or delete
            </Link>
          </nav>
        </aside>
        <main className="content" id="main">
          {page}
        </main>
      </div>
    </>
  )
}

type Step = 'password' | 'code' | 'passkey'

// production serves HTTPS; plain HTTP is a dev server, where a note on why passkeys are missing helps
const devHost = import.meta.env.DEV || location.protocol === 'http:'

function SignIn() {
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [step, setStep] = useState<Step>('password')
  const [trust, setTrust] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  // the server's RP ID, once it turns out not to be this page's host
  const [otherRp, setOtherRp] = useState<string>()
  const canPasskey = passkeysHere() && !otherRp
  const autofill = useRef<AbortController | undefined>(undefined)
  const [autofillRun, setAutofillRun] = useState(0)

  // autofill: offer this site's passkeys in the identifier field's suggestions.
  // Nobody asked for this request, so its failures (aborted, dismissed, a host
  // that can't be the RP ID) stay quiet; only a passkey picked from it can fail
  // out loud.
  useEffect(() => {
    if (!canPasskey || step !== 'password') return
    const ctl = new AbortController()
    autofill.current = ctl
    ;(async () => {
      let a: AssertionJson
      try {
        const opts = await call('vlpds.server.startPasskeySignIn', { body: {} })
        if (ctl.signal.aborted) return
        if (!rpIdHere(opts.rpId)) return setOtherRp(opts.rpId)
        if (!(await conditionalAvailable()) || ctl.signal.aborted) return
        a = await getPasskey(opts, 'conditional', ctl.signal)
      } catch {
        return
      }
      if (!ctl.signal.aborted) await run(() => finishPasskey(a))
    })()
    return () => ctl.abort()
  }, [canPasskey, step, autofillRun])

  const finishPasskey = async (credential: AssertionJson, did?: string) => {
    const owner = did ?? didOfUserHandle(credential.userHandle)
    if (!owner) throw new Error('Passkey not recognized')
    const out = await call('vlpds.server.createPasskeySession', {
      body: { did: owner, credential, trustDevice: did && trust ? true : undefined },
    })
    setSession(out)
  }

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(undefined)
    try {
      await fn()
    } catch (err) {
      if (!cancelled(err)) setError(err)
    } finally {
      setBusy(false)
    }
  }

  /** The button: passwordless, or after the password the account's passkeys as the second step. */
  const usePasskey = () =>
    run(async () => {
      // a browser runs one WebAuthn request at a time: the button's replaces autofill's
      autofill.current?.abort()
      const afterPassword = step !== 'password'
      const opts = await call('vlpds.server.startPasskeySignIn', {
        body: afterPassword ? { identifier: identifier.trim().replace(/^@/, ''), password } : {},
      })
      const a = await getPasskey(opts)
      await finishPasskey(a, afterPassword ? opts.did : undefined)
    })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    // a passkey picked from autofill mid-request would race the password's session
    autofill.current?.abort()
    void run(async () => {
      try {
        const out = await call('com.atproto.server.createSession', {
          body: {
            identifier: identifier.trim().replace(/^@/, ''),
            password,
            authFactorToken: step !== 'password' ? code.trim() : undefined,
            trustDevice: step !== 'password' && trust ? true : undefined,
          },
        })
        setSession(out)
      } catch (err) {
        if (err instanceof XrpcError && err.error === 'AuthFactorTokenRequired') {
          if (step !== 'password') throw err
          setStep('code')
        } else if (err instanceof XrpcError && err.error === 'PasskeyRequired') {
          if (step !== 'password') throw err
          setStep('passkey')
        } else throw err
      }
    }).then(() => setAutofillRun((n) => n + 1))
  }

  const back = () => {
    setStep('password')
    setCode('')
    setError(undefined)
  }

  return (
    <>
      <Topbar where="Account" />
      <main className="signin">
        <div className="card">
          <div className="inner">
            <form onSubmit={submit}>
              {step === 'password' ? (
                <>
                  <h1>Sign in</h1>
                  <p className="sub">Manage your handle, security settings and data on {location.hostname}.</p>
                  <ErrorNotice error={error} />
                  <Field label="Handle, DID or email">
                    <input
                      type="text"
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      autoComplete={canPasskey ? 'username webauthn' : 'username'}
                      autoCapitalize="none"
                      spellCheck={false}
                      required
                      autoFocus
                    />
                  </Field>
                  <Field label="Password">
                    <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
                  </Field>
                </>
              ) : (
                <>
                  <h1>Two-factor check</h1>
                  <p className="sub">
                    {step === 'passkey' ? (
                      <>
                        Use your passkey for <b>{identifier}</b>. Lost it? Enter one of your recovery codes instead.
                      </>
                    ) : (
                      <>
                        Enter the 6-digit code from your authenticator app for <b>{identifier}</b>, use your passkey, or enter one of your recovery codes.
                      </>
                    )}
                  </p>
                  {!!error && <Notice kind="err">{errText(error)}</Notice>}
                  {canPasskey && (
                    <button type="button" className="btn primary wide" onClick={usePasskey} disabled={busy} style={{ marginBottom: 14 }}>
                      {busy && <Spinner />}
                      Use your passkey
                    </button>
                  )}
                  {/* password managers pick the account's one-time code by the username beside it */}
                  <input type="text" className="sr-only" autoComplete="username" value={identifier} readOnly tabIndex={-1} aria-hidden="true" />
                  <Field label={step === 'passkey' ? 'Recovery code' : 'Authentication code'}>
                    <input
                      type="text"
                      id="totp"
                      name="totp"
                      className="code"
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      inputMode={step === 'passkey' ? undefined : 'numeric'}
                      autoComplete="one-time-code"
                      required
                      autoFocus={step === 'code'}
                    />
                  </Field>
                  <label className="check">
                    <input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} />
                    <span>
                      Trust this browser
                      <span className="small muted" style={{ display: 'block' }}>
                        Skip this step here for a while. Leave it unticked on a shared computer.
                      </span>
                    </span>
                  </label>
                </>
              )}
              <div className="row between">
                {step !== 'password' ? (
                  <button type="button" className="btn quiet" onClick={back}>
                    Use a different account
                  </button>
                ) : (
                  <Link to="/account/reset" className="small">
                    Forgot your password?
                  </Link>
                )}
                <button type="submit" className={`btn ${step === 'password' || !canPasskey ? 'primary' : ''}`} disabled={busy}>
                  {busy && <Spinner />}
                  {step !== 'password' ? 'Verify and sign in' : 'Sign in'}
                </button>
              </div>
            </form>
            {step === 'password' && canPasskey && (
              <div className="passkey-alt">
                <button type="button" className="btn wide" onClick={usePasskey} disabled={busy}>
                  Sign in with a passkey
                </button>
              </div>
            )}
            {step === 'password' && !canPasskey && devHost && (ipHost() || otherRp) && (
              <p className="small muted passkey-alt">
                Passkeys are off on {location.hostname}: {otherRp ? `they belong to ${otherRp}, the public URL's host.` : 'an IP address can’t hold them. Use a hostname such as localhost.'}
              </p>
            )}
            {step === 'password' && (
              <div className="passkey-alt">
                <ProviderSignIn />
              </div>
            )}
            {step === 'password' && (
              <p className="alt">
                New here? <Link to="/account/signup">Create an account</Link>
              </p>
            )}
          </div>
        </div>
      </main>
    </>
  )
}

/** Password reset: email a code, then set a new password with it. Also used to change a password. */
export function PasswordReset() {
  const q = useSearch()
  const [email, setEmail] = useState(q.get('email') ?? '')
  const [sent, setSent] = useState(false)
  const [token, setToken] = useState('')
  const [password, setPassword] = useState('')
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(undefined)
    try {
      await fn()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Topbar where="Account" />
      <main className="signin">
        <div className="card">
          <div className="inner">
            <h1>Reset your password</h1>
            {done ? (
              <>
                <Notice kind="ok">Password changed. Every session on this account has been signed out.</Notice>
                <div className="row end">
                  <Link to="/account" className="btn primary">
                    Sign in
                  </Link>
                </div>
              </>
            ) : !sent ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  run(async () => {
                    await call('com.atproto.server.requestPasswordReset', { body: { email: email.trim() } })
                    setSent(true)
                  })
                }}
              >
                <p className="sub">We'll email a reset code to the address on your account.</p>
                <ErrorNotice error={error} />
                <Field label="Email">
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required autoFocus />
                </Field>
                <div className="row between">
                  <Link to="/account" className="small">
                    Back to sign in
                  </Link>
                  <button className="btn primary" disabled={busy}>
                    {busy && <Spinner />}
                    Email me a code
                  </button>
                </div>
              </form>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  run(async () => {
                    await call('com.atproto.server.resetPassword', { body: { token: token.trim(), password } })
                    setSession(null)
                    setDone(true)
                  })
                }}
              >
                <p className="sub">
                  If <b>{email}</b> belongs to an account here, a code is on its way. Codes look like <span className="mono">ABCDE-12345</span>.
                </p>
                <ErrorNotice error={error} />
                <Field label="Reset code">
                  <input type="text" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="one-time-code" spellCheck={false} required autoFocus />
                </Field>
                <Field label="New password" hint="Changing your password signs out every session, including app passwords' sessions.">
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={8} required />
                </Field>
                <div className="row between">
                  <button type="button" className="btn quiet" onClick={() => setSent(false)}>
                    Send a new code
                  </button>
                  <button className="btn primary" disabled={busy}>
                    {busy && <Spinner />}
                    Change password
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      </main>
    </>
  )
}
