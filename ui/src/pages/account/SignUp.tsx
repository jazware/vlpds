import { useState, type FormEvent } from 'react'
import { DomainAffix, ErrorNotice, Field, Notice, Spinner, Topbar } from '../../components/ui'
import { domainOf } from '../../lib/domains'
import { useLoad } from '../../lib/hooks'
import { Link, navigate, useSearch } from '../../lib/router'
import { call, setSession } from '../../lib/xrpc'
import { ProviderSignIn } from './Providers'

type Describe = { availableUserDomains: string[]; inviteCodeRequired?: boolean }

/** Account creation (com.atproto.server.createAccount). Apps that want a new
 * account send people through OAuth with prompt=create, which has its own
 * server-rendered sign-up step; this page is for signing up here directly. */
export function SignUp() {
  const q = useSearch()
  const d = useLoad<Describe>(() => call('com.atproto.server.describeServer'), [])
  const [handle, setHandle] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [invite, setInvite] = useState(q.get('invite') ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const [picked, setPicked] = useState<string>()
  const domains = d.data?.availableUserDomains ?? []
  // ?domain=at.example.org: an operator's sign-up link for one of the domains
  const linked = `.${(q.get('domain') ?? '').trim().toLowerCase().replace(/^[@.]+/, '')}`
  const domain = picked ?? (domains.includes(linked) ? linked : (domains[0] ?? ''))
  const inviteRequired = !!d.data?.inviteCodeRequired
  const label = handle.trim().replace(/^@/, '').toLowerCase()
  const under = domainOf(label, domains)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    try {
      const full = under ? label : `${label}${domain}`
      const out = await call('com.atproto.server.createAccount', {
        body: { handle: full, email: email.trim(), password, inviteCode: invite.trim() || undefined },
      })
      setSession(out)
      navigate('/account', { replace: true })
    } catch (err) {
      setError(err)
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
            <form onSubmit={submit}>
              <h1>Create an account</h1>
              <p className="sub">Your repository, handle and keys live on {location.hostname}. You can move to another server later.</p>
              {d.error ? <Notice kind="err">Server info unavailable; try again shortly.</Notice> : null}
              <ErrorNotice error={error} />
              <Field label="Handle" hint="3 to 18 letters, digits or hyphens. You can switch to your own domain later.">
                <span className="affix">
                  <input
                    type="text"
                    value={handle}
                    onChange={(e) => {
                      setHandle(e.target.value)
                      const u = domainOf(e.target.value.trim().replace(/^@/, '').toLowerCase(), domains)
                      if (u) setPicked(u)
                    }}
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    minLength={3}
                    required
                    autoFocus
                  />
                  <DomainAffix
                    domains={domains}
                    value={domain}
                    onChange={(x) => {
                      setPicked(x)
                      if (under) setHandle(label.slice(0, -under.length))
                    }}
                  />
                </span>
              </Field>
              <Field label="Email" hint="For password resets and account deletion codes.">
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
              </Field>
              <Field label="Password">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  minLength={8}
                  maxLength={256}
                  required
                />
              </Field>
              {inviteRequired && (
                <Field label="Invite code" hint="This server only accepts new accounts with an invite.">
                  <input type="text" value={invite} onChange={(e) => setInvite(e.target.value)} autoCapitalize="none" spellCheck={false} required />
                </Field>
              )}
              <div className="row between">
                <Link to="/account" className="small">
                  Already have an account? Sign in
                </Link>
                <button type="submit" className="btn primary" disabled={busy || !d.data}>
                  {busy && <Spinner />}
                  Create account
                </button>
              </div>
            </form>
            <div className="passkey-alt">
              <ProviderSignIn intent="sign_up" />
            </div>
          </div>
        </div>
      </main>
    </>
  )
}
