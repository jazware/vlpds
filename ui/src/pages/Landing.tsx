import { Fragment } from 'react'
import { Topbar, CopyText, Status } from '../components/ui'
import { brand } from '../lib/brand'
import { useLoad, useSession } from '../lib/hooks'
import { Link } from '../lib/router'
import { call } from '../lib/xrpc'

type Describe = {
  did: string
  availableUserDomains: string[]
  inviteCodeRequired?: boolean
  links?: { privacyPolicy?: string; termsOfService?: string }
  contact?: { email?: string }
}

export function Landing() {
  const session = useSession()
  const d = useLoad<Describe>(() => call('com.atproto.server.describeServer'), [])
  const health = useLoad<{ version?: string }>(() => call('_health'), [])
  const [host, port] = location.host.split(':')
  const info = d.data
  return (
    <>
      <Topbar />
      <main className="landing">
        <div>
          <h1 className="host">
            {host}
            {port && <span className="port">:{port}</span>}
          </h1>
          <p className="lede">
            A personal data server for the AT Protocol. Your posts, likes and follows live here as a signed repository that any
            Bluesky-compatible app can read and write with your permission.
          </p>
          <div className="actions">
            {session ? (
              <Link to="/account" className="btn primary">
                Open your account
              </Link>
            ) : (
              <>
                <Link to="/account" className="btn primary">
                  Sign in to manage your account
                </Link>
                <Link to="/account/signup" className="btn">
                  Create an account
                </Link>
              </>
            )}
            <Link to="/admin" className="btn">
              Operator console
            </Link>
          </div>
          {/* a full page load: /migrate is served with a CSP that lets it reach your current server */}
          <a href="/migrate" className="move-here">
            Already on Bluesky? Move here <span aria-hidden="true">&rarr;</span>
          </a>
          <div className="facts">
            <dl className="dl">
              <dt>Handles</dt>
              <dd>
                {info ? (
                  info.availableUserDomains.map((x, i) => (
                    <Fragment key={x}>
                      {i > 0 && ', '}
                      <span className="mono">you{x}</span>
                    </Fragment>
                  ))
                ) : d.error ? (
                  <span className="muted">Server info unavailable</span>
                ) : (
                  <span className="muted">…</span>
                )}
              </dd>
              <dt>New accounts</dt>
              <dd>
                {info ? (
                  info.inviteCodeRequired ? (
                    <Status kind="warn">Invite code required</Status>
                  ) : (
                    <Status kind="ok">Open sign-up</Status>
                  )
                ) : (
                  '…'
                )}
              </dd>
              <dt>Service DID</dt>
              <dd>{info ? <CopyText text={info.did} /> : '…'}</dd>
              {info?.contact?.email && (
                <>
                  <dt>Contact</dt>
                  <dd>
                    <Email address={info.contact.email} />
                  </dd>
                </>
              )}
            </dl>
          </div>
        </div>
        <aside className="how" aria-labelledby="how-h">
          <div className="segments" aria-hidden="true">
            <div style={{ width: '100%' }} />
            <div style={{ width: '78%', opacity: 0.7 }} />
            <div style={{ width: '54%', opacity: 0.45 }} />
            <div style={{ width: '30%', opacity: 0.25, background: 'var(--amber)' }} />
          </div>
          <h2 id="how-h">How your data is kept</h2>
          <ol>
            <li>
              <strong>Every change is signed</strong>
              Each write becomes a commit signed with your account's key, so anyone can verify it came from you.
            </li>
            <li>
              <strong>Written to durable storage before it is confirmed</strong>
              Commits land in an append-only log in object storage; the app only hears "saved" once the log is durable.
            </li>
            <li>
              <strong>Published to the network</strong>
              The same log feeds this server's firehose, which relays and apps follow to see your updates.
            </li>
            <li>
              <strong>Yours to take elsewhere</strong>
              Export your whole repository as a CAR file at any time from your account.
            </li>
          </ol>
        </aside>
      </main>
      <footer className="footer">
        <span title={health.data?.version ? `vlpds ${health.data.version}` : undefined}>
          vlpds{health.data?.version ? <span className="mono muted"> {health.data.version.replace(/\+(.{0,12}).*/, '+$1')}</span> : null}
        </span>
        <Link to="/docs">Docs</Link>
        <a href="/xrpc/_health">Health</a>
        <a href="/.well-known/oauth-authorization-server">OAuth metadata</a>
        {info?.links?.privacyPolicy && <a href={info.links.privacyPolicy}>Privacy</a>}
        {info?.links?.termsOfService && <a href={info.links.termsOfService}>Terms</a>}
        {brand.links
          .filter((l) => l.label === 'Home' || l.label === 'Support')
          .map((l) => (
            <a key={l.label} href={l.url}>
              {l.label}
            </a>
          ))}
        {info?.contact?.email && (
          <span>
            Report abuse: <Email address={info.contact.email} />
          </span>
        )}
      </footer>
    </>
  )
}

// Spelled out and without a mailto: href in the DOM so address harvesters scraping the page don't pick it up; the
// link is only built on click.
function Email({ address }: { address: string }) {
  const at = address.lastIndexOf('@')
  if (at < 0) return <span>{address}</span>
  const [local, domain] = [address.slice(0, at), address.slice(at + 1)]
  const parts = domain.split('.')
  return (
    <a
      href="#"
      className="email"
      onClick={(e) => {
        e.preventDefault()
        location.href = `mailto:${local}@${domain}`
      }}
    >
      {local}
      <span className="sep"> [at] </span>
      {parts.map((p, i) => (
        <span key={i}>
          {i > 0 && <span className="sep"> [dot] </span>}
          {p}
        </span>
      ))}
    </a>
  )
}
