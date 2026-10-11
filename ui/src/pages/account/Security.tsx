import { useState } from 'react'
import { QR } from '../../components/QR'
import { Confirm, CopyText, Empty, ErrorNotice, Field, Loading, Notice, PageHead, Panel, Spinner, Status } from '../../components/ui'
import { fmtTime } from '../../lib/format'
import { useAction, useLoad, useSession } from '../../lib/hooks'
import { Link } from '../../lib/router'
import { acall, call, setSession } from '../../lib/xrpc'
import { RecoveryKeys } from './RecoveryKeys'
import { SignInSecurity } from './SignIns'
import { Passkeys, RecoveryCodes, SavedCodes } from './Passkeys'
import { WaysToSignIn } from './Providers'

export function Security() {
  const [ver, setVer] = useState(0)
  return (
    <>
      <PageHead title="Security" desc="Passkeys and two-factor sign-in, where you've signed in, your recovery key, passwords for apps, and the apps you've connected." />
      <WaysToSignIn />
      <Passkeys onChange={() => setVer((v) => v + 1)} />
      <Totp onChange={() => setVer((v) => v + 1)} />
      <RecoveryCodes ver={ver} />
      <SignInSecurity ver={ver} />
      <RecoveryKeys />
      <AppPasswords />
      <ConnectedApps />
      <ChangePassword />
    </>
  )
}

// ---------------------------------------------------------------- TOTP

type TotpStatus = { enabled: boolean; pending: boolean; recoveryCodesRemaining: number; enabledAt?: string }

function Totp({ onChange }: { onChange: () => void }) {
  const st = useLoad<TotpStatus>(() => acall('vlpds.server.getTotpStatus'), [])
  const s = useSession()!
  const [setup, setSetup] = useState<{ secret: string; uri: string }>()
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[]>()
  const [disabling, setDisabling] = useState(false)
  const [pw, setPw] = useState('')
  const [dcode, setDcode] = useState('')

  const begin = useAction(async () => setSetup(await acall('vlpds.server.setupTotp', { method: 'POST' })))
  const confirm = useAction(async () => {
    const r = await acall('vlpds.server.confirmTotp', { body: { code: code.replace(/\s/g, '') } })
    setCodes(r.recoveryCodes?.length ? r.recoveryCodes : undefined)
    setSetup(undefined)
    setCode('')
    st.reload()
    onChange()
  })
  const disable = useAction(async () => {
    const c = dcode.replace(/\s/g, '')
    await acall('vlpds.server.disableTotp', { body: { password: pw, ...(/^\d{6}$/.test(c) ? { code: c } : { recoveryCode: dcode.trim() }) } })
    setDisabling(false)
    setPw('')
    setDcode('')
    st.reload()
    onChange()
  })

  const desc = 'Ask for a code from an authenticator app whenever someone signs in with your password. App passwords are not affected.'
  if (codes) return <SavedCodes codes={codes} handle={s.handle} onDone={() => setCodes(undefined)} />

  return (
    <Panel title="Two-factor sign-in" desc={desc} id="totp">
      <ErrorNotice error={st.error} />
      {!st.data ? (
        !st.error && <Loading />
      ) : st.data.enabled ? (
        <>
          <dl className="dl" style={{ marginBottom: 14 }}>
            <dt>Status</dt>
            <dd>
              <Status kind="ok">On</Status>
            </dd>
            <dt>Turned on</dt>
            <dd>{fmtTime(st.data.enabledAt)}</dd>
            <dt>Recovery codes left</dt>
            <dd>
              {st.data.recoveryCodesRemaining}
              {st.data.recoveryCodesRemaining < 3 && <span className="muted"> — get a fresh set under Recovery codes</span>}
            </dd>
          </dl>
          {!disabling ? (
            <button className="btn danger" onClick={() => setDisabling(true)}>
              Turn off two-factor
            </button>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                disable.run()
              }}
            >
              <ErrorNotice error={disable.error} />
              <Field label="Password">
                <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required autoFocus />
              </Field>
              <Field label="Authenticator code or recovery code">
                <input type="text" value={dcode} onChange={(e) => setDcode(e.target.value)} autoComplete="one-time-code" spellCheck={false} required />
              </Field>
              <div className="row">
                <button type="button" className="btn" onClick={() => setDisabling(false)}>
                  Cancel
                </button>
                <button className="btn danger solid" disabled={disable.busy}>
                  {disable.busy && <Spinner />}
                  Turn off two-factor
                </button>
              </div>
            </form>
          )}
        </>
      ) : !setup ? (
        <>
          <ErrorNotice error={begin.error} />
          <div className="row">
            <Status kind="idle">Off</Status>
            <div style={{ flex: 1 }} />
            <button className="btn primary" onClick={() => begin.run()} disabled={begin.busy}>
              {begin.busy && <Spinner />}
              Set up authenticator app
            </button>
          </div>
        </>
      ) : (
        <div className="totp-setup">
          <QR text={setup.uri} label="QR code for your authenticator app" />
          <form
            onSubmit={(e) => {
              e.preventDefault()
              confirm.run()
            }}
          >
            <p>Scan the code with an authenticator app such as 1Password, Google Authenticator or Authy. Can't scan it? Enter this key instead:</p>
            <div className="secret" style={{ marginBottom: 14 }}>
              <CopyText text={setup.secret} display={setup.secret.match(/.{1,4}/g)?.join(' ')} />
            </div>
            <ErrorNotice error={confirm.error} />
            <Field label="Code shown in the app">
              <input
                type="text"
                className="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9 ]{6,7}"
                required
                autoFocus
              />
            </Field>
            <div className="row">
              <button type="button" className="btn" onClick={() => setSetup(undefined)}>
                Cancel
              </button>
              <button className="btn primary" disabled={confirm.busy}>
                {confirm.busy && <Spinner />}
                Turn on two-factor
              </button>
            </div>
          </form>
        </div>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------- app passwords

type AppPassword = { name: string; createdAt: string; privileged: boolean; scopes?: string }

type Access = 'full' | 'post' | 'read' | 'custom'

const POST_ONLY_SCOPES =
  'atproto repo?collection=app.bsky.feed.like&collection=app.bsky.feed.post&collection=app.bsky.feed.repost&collection=app.bsky.graph.follow&action=create&action=delete blob:*/*'

function readOnlyScopes(appviewAud: string) {
  return `atproto rpc:*?aud=${appviewAud.replace('#', '%23')}`
}

function accessOf(p: AppPassword, appviewAud?: string): Access {
  if (!p.scopes) return 'full'
  if (p.scopes === POST_ONLY_SCOPES) return 'post'
  if (appviewAud && p.scopes === readOnlyScopes(appviewAud)) return 'read'
  return 'custom'
}

function AccessSummary({ p, appviewAud }: { p: AppPassword; appviewAud?: string }) {
  switch (accessOf(p, appviewAud)) {
    case 'full':
      return p.privileged ? <span className="pill amber">Full access, includes DMs</span> : <span className="pill">Full access</span>
    case 'post':
      return <span className="pill">Post only</span>
    case 'read':
      return <span className="pill">Read only</span>
    case 'custom':
      return (
        <div className="row" style={{ gap: 4 }}>
          <span className="pill amber">Custom{p.privileged ? ', DMs allowed' : ''}</span>
          {p.scopes!.split(' ').map((sc) => (
            <span key={sc} className="pill mono">
              {sc}
            </span>
          ))}
        </div>
      )
  }
}

function AppPasswords() {
  const list = useLoad<{ passwords: AppPassword[]; appviewAud?: string }>(() => acall('com.atproto.server.listAppPasswords'), [])
  const appviewAud = list.data?.appviewAud
  const [name, setName] = useState('')
  const [access, setAccess] = useState<Access>('full')
  const [custom, setCustom] = useState('')
  const [privileged, setPrivileged] = useState(false)
  const [created, setCreated] = useState<{ name: string; password: string }>()
  const [revoking, setRevoking] = useState<string>()
  const create = useAction(async () => {
    const scopes =
      access === 'post' ? POST_ONLY_SCOPES : access === 'read' && appviewAud ? readOnlyScopes(appviewAud) : access === 'custom' ? custom.trim() : undefined
    const dms = privileged && (access === 'full' || access === 'custom')
    const r = await acall('com.atproto.server.createAppPassword', { body: { name: name.trim(), privileged: dms, ...(scopes ? { scopes } : {}) } })
    setCreated(r)
    setName('')
    setAccess('full')
    setCustom('')
    setPrivileged(false)
    list.reload()
  })
  const choice = (value: Access, title: string, desc: string) => (
    <label className="ap-choice">
      <input type="radio" name="ap-access" checked={access === value} onChange={() => setAccess(value)} />
      <div>
        <strong>{title}</strong>
        <div className="small muted">{desc}</div>
      </div>
    </label>
  )
  const revoke = useAction(async (n: string) => {
    await acall('com.atproto.server.revokeAppPassword', { body: { name: n } })
    setRevoking(undefined)
    list.reload()
  })
  const pws = list.data?.passwords ?? []
  return (
    <Panel title="App passwords" desc="Separate passwords for apps that don't support OAuth. They can't change your password, email or two-factor settings." id="app-passwords">
      {created && (
        <Notice kind="ok">
          <p>
            <b>{created.name}</b> created. Copy it now: it won't be shown again.
          </p>
          <div className="password-once">
            <CopyText text={created.password} />
          </div>
          <button className="btn sm" onClick={() => setCreated(undefined)}>
            Done
          </button>
        </Notice>
      )}
      <ErrorNotice error={list.error || revoke.error} />
      {list.loading && !list.data ? (
        <Loading />
      ) : pws.length === 0 ? (
        <Empty title="No app passwords">Create one below for an app that asks for your password.</Empty>
      ) : (
        <div className="table-wrap" style={{ margin: '0 -18px 16px' }}>
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th>Created</th>
                <th>Access</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {pws.map((p) => (
                <tr key={p.name}>
                  <td className="break">
                    <b>{p.name}</b>
                  </td>
                  <td className="nowrap">{fmtTime(p.createdAt)}</td>
                  <td>
                    <AccessSummary p={p} appviewAud={appviewAud} />
                  </td>
                  <td className="num">
                    <button className="btn danger sm" onClick={() => setRevoking(p.name)}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ErrorNotice error={create.error} />
      <form
        onSubmit={(e) => {
          e.preventDefault()
          create.run()
        }}
      >
        <Field label="New app password name">
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Graysky on my phone" maxLength={64} required />
        </Field>
        <div role="radiogroup" aria-label="What the app may do">
          <p className="small muted" style={{ margin: '0 0 8px' }}>
            What may the app do?
          </p>
          {choice('full', 'Full access', 'Everything a Bluesky app needs: read your feeds, post, follow, edit your profile and settings.')}
          {choice(
            'post',
            'Post only',
            "Post, delete posts, like, repost, follow and upload images. It can't read your feeds or notifications, change your profile, or see DMs. Good for bots."
          )}
          {appviewAud &&
            choice(
              'read',
              'Read only',
              "Read your timeline, profiles and notifications. It can't post, like, follow, upload or change your profile. It can still change app settings kept with Bluesky, such as mutes, saved feeds and which notifications you've seen."
            )}
          {choice('custom', 'Custom', 'Pick exactly what it may do, written as OAuth permissions. For developers.')}
        </div>
        {access === 'custom' && (
          <Field
            label="Permissions"
            hint={
              <>
                Space-separated OAuth scopes, e.g. <span className="mono">repo:app.bsky.feed.post blob:image/*</span>. DMs need a chat scope too, such as{' '}
                <span className="mono">transition:chat.bsky</span>.
              </>
            }
          >
            <textarea className="mono" value={custom} onChange={(e) => setCustom(e.target.value)} rows={3} required maxLength={2048} />
          </Field>
        )}
        {(access === 'full' || access === 'custom') && (
          <label className="check">
            <input type="checkbox" checked={privileged} onChange={(e) => setPrivileged(e.target.checked)} />
            <span>Allow access to direct messages</span>
          </label>
        )}
        <div className="row end">
          <button className="btn primary" disabled={create.busy}>
            {create.busy && <Spinner />}
            Create password
          </button>
        </div>
      </form>
      <Confirm
        open={!!revoking}
        title={`Revoke “${revoking}”?`}
        action="Revoke password"
        danger
        busy={revoke.busy}
        onConfirm={() => revoking && revoke.run(revoking)}
        onClose={() => setRevoking(undefined)}
      >
        Apps using this password are signed out immediately.
      </Confirm>
    </Panel>
  )
}

// ---------------------------------------------------------------- OAuth apps

type OAuthSession = { id: string; clientId: string; scope: string; createdAt: string; updatedAt: string; accessExpiresAt: string }

function clientName(id: string) {
  try {
    const u = new URL(id)
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') return 'Development app on this computer'
    return u.hostname
  } catch {
    return id
  }
}

function ConnectedApps() {
  const list = useLoad<{ sessions: OAuthSession[] }>(() => acall('vlpds.oauth.listSessions'), [])
  const [revoking, setRevoking] = useState<OAuthSession>()
  const revoke = useAction(async (id: string) => {
    await acall('vlpds.oauth.revokeSession', { body: { id } })
    setRevoking(undefined)
    list.reload()
  })
  const ss = list.data?.sessions ?? []
  return (
    <Panel title="Connected apps" desc="Apps you've signed in to with this account through OAuth." id="oauth" flush={ss.length > 0}>
      <ErrorNotice error={list.error || revoke.error} />
      {list.loading && !list.data ? (
        <Loading />
      ) : ss.length === 0 ? (
        <Empty title="No connected apps">When you sign in to an app with your handle, it shows up here.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>App</th>
                <th>Permissions</th>
                <th className="hide-sm">Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {ss.map((x) => (
                <tr key={x.id}>
                  <td>
                    <b className="break">{clientName(x.clientId)}</b>
                    <div className="mono small muted break">{x.clientId}</div>
                    <div className="small muted">Authorized {fmtTime(x.createdAt)}</div>
                  </td>
                  <td>
                    <div className="row" style={{ gap: 4 }}>
                      {x.scope.split(' ').map((sc) => (
                        <span key={sc} className="pill mono">
                          {sc}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="nowrap hide-sm">{fmtTime(x.updatedAt)}</td>
                  <td className="num">
                    <button className="btn danger sm" onClick={() => setRevoking(x)}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Confirm
        open={!!revoking}
        title={`Disconnect ${revoking ? clientName(revoking.clientId) : ''}?`}
        action="Revoke access"
        danger
        busy={revoke.busy}
        onConfirm={() => revoking && revoke.run(revoking.id)}
        onClose={() => setRevoking(undefined)}
      >
        The app loses access to your account right away. You can connect it again by signing in from the app.
      </Confirm>
    </Panel>
  )
}

// ---------------------------------------------------------------- password

function ChangePassword() {
  const s = useSession()!
  const [sent, setSent] = useState(false)
  const [token, setToken] = useState('')
  const [password, setPassword] = useState('')
  const request = useAction(async () => {
    const info = await acall('com.atproto.server.getSession')
    if (!info.email) throw new Error('Add an email address first: password changes are confirmed by email.')
    await call('com.atproto.server.requestPasswordReset', { body: { email: info.email } })
    setSent(true)
  })
  const reset = useAction(async () => {
    await call('com.atproto.server.resetPassword', { body: { token: token.trim(), password } })
    setSession(null)
  })
  return (
    <Panel title="Password" desc="Changing your password signs out every session and app password session on this account, and removes every trusted browser." id="password">
      <ErrorNotice error={request.error || reset.error} />
      {!sent ? (
        <div className="row">
          <button className="btn" onClick={() => request.run()} disabled={request.busy}>
            {request.busy && <Spinner />}
            Email me a code to change it
          </button>
          <span className="small muted">
            Signed out? Use <Link to="/account/reset">password reset</Link>.
          </span>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            reset.run()
          }}
        >
          <Notice>We emailed a code to the address on @{s.handle}.</Notice>
          <Field label="Code">
            <input type="text" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="one-time-code" spellCheck={false} required autoFocus />
          </Field>
          <Field label="New password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={8} required />
          </Field>
          <div className="row">
            <button type="button" className="btn" onClick={() => setSent(false)}>
              Cancel
            </button>
            <button className="btn primary" disabled={reset.busy}>
              {reset.busy && <Spinner />}
              Change password and sign out
            </button>
          </div>
        </form>
      )}
    </Panel>
  )
}
