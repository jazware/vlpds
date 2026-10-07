import { useState, type JSX, type ReactNode } from 'react'
import '../../console.css'
import { DetailPage, detailKind } from '../../components/console/Drawer'
import { Empty } from '../../components/console/kit'
import { Shell } from '../../components/console/Shell'
import { SECTION, sectionOf, type Section } from '../../components/console/sections'
import { ErrorNotice, Field, Spinner, Topbar } from '../../components/ui'
import { useAdminToken } from '../../lib/hooks'
import { Link, match } from '../../lib/router'
import { basic, call, setAdminToken } from '../../lib/xrpc'
import { Accounts } from './Accounts'
import { Cluster } from './Cluster'
import './clusterDetails'
import { Config } from './Config'
import { Domains } from './Domains'
import { Firehose } from './Firehose'
import { Mail } from './Mail'
import { Metrics } from './Metrics'
import { Moderation } from './Moderation'
import { Nodes } from './Nodes'
import { Overview } from './Overview'
import { Legacy } from './Placeholder'
import { Limits } from './Limits'
import { SpaceByUri, Spaces } from './Spaces'
import { Storage } from './Storage'
import './systemDetails'

// The operator console: the token gate, then the shell around one page per route. Sections
// still on their pre-console pages render them inside <Legacy> until they're rebuilt
// (CONSOLE.md lists which).

type Route = { section: Section; page: JSX.Element; crumbs?: ReactNode }

const crumb = (section: Section, last: ReactNode) => (
  <>
    <Link to={section.path}>{section.label}</Link>
    <span className="sep">/</span>
    <b>{last}</b>
  </>
)

function route(p: string): Route {
  let m: Record<string, string> | null
  const S = SECTION
  switch (p) {
    case '/admin':
      return { section: S.overview, page: <Overview /> }
    case '/admin/nodes':
      return { section: S.nodes, page: <Nodes /> }
    case '/admin/metrics':
      return { section: S.nodes, page: <Metrics />, crumbs: crumb(S.nodes, 'Live metrics') }
    case '/admin/cluster':
      return { section: S.nodes, page: <Legacy><Cluster /></Legacy>, crumbs: crumb(S.nodes, 'Classic view') }
    case '/admin/storage':
      return { section: S.storage, page: <Storage /> }
    case '/admin/firehose':
    case '/admin/relays':
      return { section: S.firehose, page: <Firehose /> }
    case '/admin/accounts':
      return { section: S.accounts, page: <Accounts /> }
    case '/admin/moderation':
      return { section: S.moderation, page: <Moderation /> }
    case '/admin/limits':
    case '/admin/ratelimits':
      return { section: S.limits, page: <Limits /> }
    case '/admin/domains':
    case '/admin/invites':
    case '/admin/handle-domains':
      return { section: S.domains, page: <Domains /> }
    case '/admin/spaces':
      return { section: S.spaces, page: <Spaces /> }
    case '/admin/spaces/space':
      return { section: S.spaces, page: <SpaceByUri />, crumbs: crumb(S.spaces, 'Space') }
    case '/admin/mail':
      return { section: S.mail, page: <Mail /> }
    case '/admin/config':
      return { section: S.config, page: <Config /> }
  }
  // the pre-console account page's path, which other pages still link to
  if ((m = match('/admin/accounts/:did', p)) && m.did.startsWith('did:')) return { section: S.accounts, page: <DetailPage key="account" type="account" id={m.did} />, crumbs: crumb(S.accounts, m.did) }
  if ((m = match('/admin/moderation/cases/:id', p))) return { section: S.moderation, page: <DetailPage key="case" type="case" id={m.id} />, crumbs: crumb(S.moderation, m.id) }
  // a detail kind's full page: /admin/<section>/<type>/<id>
  if ((m = match('/admin/:section/:type/:id', p)) && detailKind(m.type)) {
    const section = sectionOf(p)
    return { section, page: <DetailPage key={m.type} type={m.type} id={m.id} />, crumbs: crumb(section, m.id) }
  }
  return { section: sectionOf(p), page: <Empty title="No such page">There is no console page at {p}.</Empty> }
}

export function AdminApp({ path }: { path: string }) {
  const token = useAdminToken()
  if (!token) return <AdminLogin />
  const r = route(path.replace(/\/+$/, '') || '/admin')
  return (
    <Shell section={r.section} crumbs={r.crumbs}>
      {r.page}
    </Shell>
  )
}

function AdminLogin() {
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  return (
    <>
      <Topbar where="Operator console" />
      <main className="signin">
        <div className="card">
          <div className="inner">
            <form
              onSubmit={async (e) => {
                e.preventDefault()
                setBusy(true)
                setError(undefined)
                try {
                  await call('vlpds.admin.getClusterStatus', { auth: basic(token.trim()) })
                  setAdminToken(token.trim())
                } catch (err) {
                  setError(err)
                } finally {
                  setBusy(false)
                }
              }}
            >
              <h1>Operator console</h1>
              <p className="sub">Cluster health, live metrics and account administration. The token stays in this tab only.</p>
              <ErrorNotice error={error} />
              <Field label="Admin token" hint="The server's --admin-token (VLPDS_ADMIN_TOKEN).">
                <input type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required autoFocus />
              </Field>
              <div className="row end">
                <button className="btn primary" disabled={busy}>
                  {busy && <Spinner />}
                  Unlock console
                </button>
              </div>
            </form>
          </div>
        </div>
      </main>
    </>
  )
}
