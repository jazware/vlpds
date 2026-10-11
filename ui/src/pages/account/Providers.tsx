import { useEffect, useState } from 'react'
import { ErrorNotice, Field, Notice, Panel, Spinner, Topbar } from '../../components/ui'
import {
  link,
  methods,
  proceed,
  redeem,
  reauth,
  signMessage,
  start,
  walletAddress,
  type Credential,
  type Progress,
  type Provider,
} from '../../lib/auth'
import { useSession } from '../../lib/hooks'
import { Link, navigate } from '../../lib/router'
import { acall, setSession } from '../../lib/xrpc'

/** A link or unlink in flight while the browser is away at a provider. */
type PendingAction = { kind: 'link' | 'unlink'; id?: string; provider: string }

const PENDING_KEY = 'vlpds.auth.pending'

export function rememberPending(a: PendingAction) {
  try {
    sessionStorage.setItem(PENDING_KEY, JSON.stringify(a))
  } catch {
    /* storage blocked */
  }
}

export function takePending(): PendingAction | undefined {
  try {
    const s = sessionStorage.getItem(PENDING_KEY)
    if (!s) return undefined
    sessionStorage.removeItem(PENDING_KEY)
    return JSON.parse(s) as PendingAction
  } catch {
    return undefined
  }
}

/** Run a challenge: a wallet signs in place; anything else is a redirect. */
async function runChallenge(challenge: { kind: string; url?: string; message?: string; address?: string }) {
  if (challenge.kind === 'redirect' && challenge.url) {
    location.assign(challenge.url)
    return undefined
  }
  if (challenge.kind !== 'siwe' || !challenge.message) throw new Error('The server returned an unexpected challenge.')
  const address = challenge.address ?? (await walletAddress())
  const signature = await signMessage(challenge.message, address)
  return { address, message: challenge.message, signature }
}

/** The fields a sign-up collects: by then the identity is already proved. */
type SignupValues = { handle: string; domain: string; email: string; invite: string }

function SignupFields({
  values,
  domains,
  inviteRequired,
  onChange,
}: {
  values: SignupValues
  domains: string[]
  inviteRequired: boolean
  onChange: (v: SignupValues) => void
}) {
  return (
    <>
      <Field label="Handle" hint="3 to 18 letters, digits or hyphens. You can switch to your own domain later.">
        <span className="affix">
          <input
            type="text"
            value={values.handle}
            onChange={(e) => onChange({ ...values, handle: e.target.value })}
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
          />
          <span className="suffix">
            {domains.length > 1 ? (
              <select value={values.domain} onChange={(e) => onChange({ ...values, domain: e.target.value })}>
                {domains.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            ) : (
              <span className="muted">{values.domain}</span>
            )}
          </span>
        </span>
      </Field>
      <Field label="Email" hint="For password resets and account deletion codes.">
        <input type="email" value={values.email} onChange={(e) => onChange({ ...values, email: e.target.value })} />
      </Field>
      {inviteRequired && (
        <Field label="Invite code" hint="This server only accepts new accounts with an invite.">
          <input
            type="text"
            value={values.invite}
            onChange={(e) => onChange({ ...values, invite: e.target.value })}
            autoCapitalize="none"
            spellCheck={false}
          />
        </Field>
      )}
    </>
  )
}

/** Create the account a proved identity asked for, then take the session it
 * comes with. The server has already checked the identity. */
async function submitSignup(txn: string, v: SignupValues): Promise<void> {
  const done = await proceed({
    txn,
    step: 'signup',
    handle: v.handle.trim(),
    domain: v.domain,
    email: v.email.trim(),
    inviteCode: v.invite.trim() || undefined,
  })
  if (done.status !== 'done') throw new Error('The sign-up did not complete.')
  const session = await redeem()
  if (session) setSession(session)
}

/** Sign-in buttons for the configured methods. */
export function ProviderSignIn({ intent = 'sign_in' as const, onSignedIn }: { intent?: 'sign_in' | 'sign_up'; onSignedIn?: () => void }) {
  const [list, setList] = useState<Provider[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [signupTxn, setSignupTxn] = useState<string>()
  const [values, setValues] = useState<SignupValues>({ handle: '', domain: '', email: '', invite: '' })
  const [domains, setDomains] = useState<string[]>([])
  const [inviteRequired, setInviteRequired] = useState(false)

  useEffect(() => {
    void methods().then(setList).catch(() => {})
    void acall('com.atproto.server.describeServer')
      .then((d: { availableUserDomains?: string[]; inviteCodeRequired?: boolean }) => {
        setDomains(d.availableUserDomains ?? [])
        setInviteRequired(!!d.inviteCodeRequired)
      })
      .catch(() => {})
  }, [])

  const finish = async (p: Progress) => {
    if (p.status === 'done') {
      const s = await redeem()
      if (s) setSession(s)
      onSignedIn?.()
      return
    }
    if (p.status === 'factor') {
      location.assign(p.url)
      return
    }
    if (p.status === 'signup') {
      setSignupTxn(p.txnId)
      setValues((v) => ({ ...v, email: p.email ?? v.email, domain: domains[0] ?? v.domain }))
      return
    }
    throw new Error('The server returned an unexpected answer.')
  }

  const choose = async (p: Provider) => {
    setBusy(true)
    setError(undefined)
    try {
      const s = await start(p.id, intent)
      const signed = await runChallenge(s.challenge)
      if (!signed) return
      await finish(await proceed({ txn: s.txnId, step: 'siwe', ...signed }))
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  if (!list.length) return null
  // Every configured method can start a sign-up now: a wallet in place, and a
  // redirect provider by coming back to the account page for its fields.
  const offered = list

  if (signupTxn) {
    return (
      <div className="stack">
        <h2>Finish creating your account</h2>
        <ErrorNotice error={error} />
        <SignupFields values={values} domains={domains} inviteRequired={inviteRequired} onChange={setValues} />
        <div className="row">
          <button type="button" className="btn" onClick={() => setSignupTxn(undefined)}>
            Back
          </button>
          <button
            type="button"
            className="btn primary"
            disabled={busy || !values.handle.trim() || !values.email.trim() || (inviteRequired && !values.invite.trim())}
            onClick={() =>
              void (async () => {
                setBusy(true)
                setError(undefined)
                try {
                  await submitSignup(signupTxn, values)
                  onSignedIn?.()
                } catch (e) {
                  setError(e)
                } finally {
                  setBusy(false)
                }
              })()
            }
          >
            {busy && <Spinner />}
            Create account
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="stack">
      <ErrorNotice error={error} />
      {offered.map((p) => (
        <button key={p.id} type="button" className="btn wide" disabled={busy} onClick={() => void choose(p)}>
          {busy && <Spinner />}
          Continue with {p.label}
        </button>
      ))}
    </div>
  )
}

/** Finish a link or confirmation the browser left for at a provider: the
 * transaction id and step come back in the URL. */
export async function finishPendingReturn(txn: string, step: 'link' | 'reauth', token: string) {
  const pending = takePending()
  const done = await proceed({ txn, step })
  if (!pending) return
  if (step !== 'reauth' || done.status !== 'confirmed') return
  if (pending.kind === 'unlink' && pending.id) {
    await acall('vlpds.auth.unlinkCredential', { body: { id: pending.id, grant: done.grant } })
    return
  }
  const address = pending.provider === 'siwe' ? await walletAddress() : undefined
  const started = await link(pending.provider, { token, address, grant: done.grant })
  const signed = await runChallenge(started.challenge)
  if (signed) await proceed({ txn: started.txnId, step: 'link', ...signed })
}

/** Finishing a sign-up that started at a provider which redirects: the
 * identity was proved before the browser came back, so this only collects the
 * account's own fields. The account page renders it for `?auth=signup&t=…`. */
export function ProviderSignup({ txn }: { txn: string }) {
  const [values, setValues] = useState<SignupValues>({ handle: '', domain: '', email: '', invite: '' })
  const [domains, setDomains] = useState<string[]>([])
  const [inviteRequired, setInviteRequired] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()

  useEffect(() => {
    void acall('com.atproto.server.describeServer')
      .then((d: { availableUserDomains?: string[]; inviteCodeRequired?: boolean }) => {
        const available = d.availableUserDomains ?? []
        setDomains(available)
        setInviteRequired(!!d.inviteCodeRequired)
        setValues((v) => ({ ...v, domain: available[0] ?? '' }))
      })
      .catch(() => {})
  }, [])

  return (
    <>
      <Topbar where="Account" />
      <main className="signin">
        <div className="card">
          <div className="inner">
            <form
              onSubmit={(e) => {
                e.preventDefault()
                void (async () => {
                  setBusy(true)
                  setError(undefined)
                  try {
                    await submitSignup(txn, values)
                    navigate('/account', { replace: true })
                  } catch (err) {
                    setError(err)
                  } finally {
                    setBusy(false)
                  }
                })()
              }}
            >
              <h1>Finish creating your account</h1>
              <p className="sub">Your repository, handle and keys will live on {location.hostname}.</p>
              <ErrorNotice error={error} />
              <SignupFields values={values} domains={domains} inviteRequired={inviteRequired} onChange={setValues} />
              <div className="row between">
                <Link to="/account" className="small">
                  Cancel
                </Link>
                <button
                  type="submit"
                  className="btn primary"
                  disabled={busy || !values.handle.trim() || !values.email.trim() || (inviteRequired && !values.invite.trim())}
                >
                  {busy && <Spinner />}
                  Create account
                </button>
              </div>
            </form>
          </div>
        </div>
      </main>
    </>
  )
}

/** The account's own ways to sign in: list, attach, remove. */
export function WaysToSignIn() {
  const s = useSession()
  const [state, setState] = useState<{ credentials: Credential[]; hasPassword: boolean }>()
  const [error, setError] = useState<unknown>()
  const [busy, setBusy] = useState(false)
  const [adding, setAdding] = useState<Provider[]>([])
  const [password, setPassword] = useState('')
  const [removing, setRemoving] = useState<Credential>()

  const reload = () => acall<{ credentials: Credential[]; hasPassword: boolean }>('vlpds.auth.listCredentials').then(setState)
  useEffect(() => {
    void reload().catch(setError)
    void methods()
      .then((all) => setAdding(all))
      .catch(() => {})
  }, [])

  if (!s) return null
  const creds = state?.credentials ?? []

  /** Confirm a change with a method the account already has, then act. */
  const confirmAnd = async (p: Provider, action: 'link' | 'unlink', target: string, credId?: string) => {
    setBusy(true)
    setError(undefined)
    try {
      rememberPending({ kind: action, id: credId, provider: p.id })
      // A wallet's address is needed before its challenge can be built.
      const address = p.id === 'siwe' ? await walletAddress() : undefined
      const started = await reauth(p.id, action, target, { token: s.accessJwt, address })
      const signed = await runChallenge(started.challenge)
      if (!signed) return // the browser is leaving for the provider
      const done = await proceed({ txn: started.txnId, step: 'reauth', ...signed })
      if (done.status !== 'confirmed') throw new Error('The confirmation did not complete.')
      await apply(done.grant, action, target, credId)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  const apply = async (grant: string, action: 'link' | 'unlink', target: string, credId?: string) => {
    if (action === 'unlink' && credId) {
      await acall('vlpds.auth.unlinkCredential', { body: { id: credId, grant } })
    } else {
      const address = target === 'siwe' ? await walletAddress() : undefined
      const started = await link(target, { token: s.accessJwt, address, grant })
      const signed = await runChallenge(started.challenge)
      if (!signed) return
      const done = await proceed({ txn: started.txnId, step: 'link', ...signed })
      if (done.status !== 'linked') throw new Error('The method was not attached.')
    }
    takePending()
    await reload()
  }

  const attach = async (p: Provider) => {
    setBusy(true)
    setError(undefined)
    try {
      if (state?.hasPassword) {
        const address = p.presentation === 'siwe' ? await walletAddress() : undefined
        const started = await link(p.id, { token: s.accessJwt, address, password })
        const signed = await runChallenge({ ...started.challenge, address })
        if (!signed) return
        const done = await proceed({ txn: started.txnId, step: 'link', ...signed })
        if (done.status !== 'linked') throw new Error('The method was not attached.')
        setPassword('')
        await reload()
        return
      }
      // Provider-only account: prove one you already have first.
      const existing = creds[0]
      await confirmAnd({ id: existing.provider, label: existing.label ?? existing.provider, presentation: 'siwe' }, 'link', p.id)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  const unlink = async () => {
    const c = removing
    if (!c) return
    setBusy(true)
    setError(undefined)
    try {
      await confirmAnd({ id: c.provider, label: c.label ?? c.provider, presentation: 'siwe' }, 'unlink', c.id, c.id)
      setRemoving(undefined)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel
      title="Ways to sign in"
      id="ways-to-sign-in"
      desc="Anyone who controls one of these can sign in as you. Changing them needs a fresh proof that it is you."
    >
      <ErrorNotice error={error} />
      {!state ? (
        <Spinner />
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Account</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {state.hasPassword && (
                  <tr>
                    <td>Password</td>
                    <td className="muted">Set on this server</td>
                    <td />
                  </tr>
                )}
                {creds.map((c) => (
                  <tr key={c.id}>
                    <td>{c.provider === 'siwe' ? 'Ethereum' : c.provider === 'google' ? 'Google' : 'Apple'}</td>
                    <td className="mono small">{c.label ?? '—'}</td>
                    <td className="nowrap">
                      <button
                        type="button"
                        className="btn sm danger"
                        disabled={busy}
                        onClick={() => {
                          setRemoving(c)
                          setPassword('')
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {removing && (
            <Notice kind="warn">
              <p>
                Removing this needs a fresh proof: you will confirm with the{' '}
                {removing.provider === 'siwe' ? 'wallet' : removing.provider} itself
                {state.hasPassword ? ', or with your password' : ''}.
              </p>
              {state.hasPassword && (
                <Field label="Password" hint="Used to start the confirmation.">
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
                </Field>
              )}
              <div className="row">
                <button type="button" className="btn" onClick={() => setRemoving(undefined)}>
                  Cancel
                </button>
                <button type="button" className="btn danger solid" disabled={busy} onClick={() => void unlink()}>
                  {busy && <Spinner />}
                  Remove
                </button>
              </div>
            </Notice>
          )}
          {adding.length > 0 && (
            <div className="stack" style={{ marginTop: 14 }}>
              <h3>Add another method</h3>
              {adding
                .filter((p) => !creds.some((c) => c.provider === p.id))
                .map((p) => (
                  <button key={p.id} type="button" className="btn wide" disabled={busy} onClick={() => void attach(p)}>
                    {busy && <Spinner />}
                    Add {p.label}
                  </button>
                ))}
            </div>
          )}
        </>
      )}
    </Panel>
  )
}