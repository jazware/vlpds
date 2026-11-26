// `npm run dev:mock` serves the console and account pages without a server: this plugin answers
// the few /xrpc methods they need from memory (writes stick until the dev server restarts).
// VLPDS_MOCK_LEVEL=1 shows the sign-in providers page below feature level 2.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const env = (k) => (typeof process !== 'undefined' ? process.env[k] : undefined)
const now = Date.now()
const iso = (ago) => new Date(now - ago).toISOString()
const dot = (c) => `data:image/svg+xml;base64,${Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="${c}"/></svg>`).toString('base64')}`

const view = (p) => ({
  icon: null,
  callbackUrl: `https://pds.example.com/oauth/federated/callback/${p.id}`,
  scopes: ['openid', 'email'],
  responseMode: 'query',
  signup: 'off',
  signupsPerDay: 100,
  trustEmail: false,
  requiredClaims: {},
  idTokenAlgs: [],
  updatedBy: 'alex',
  ...p,
})

const seed = () => [
  view({
    id: 'google',
    name: 'Google',
    icon: dot('#4285f4'),
    issuer: 'https://accounts.example.com',
    clientId: '1234.apps.example.com',
    clientAuth: { method: 'client_secret_basic', secret: { stored: 'wrapped' }, key: null, keyId: null, signedSecret: null },
    trustEmail: true,
    requiredClaims: { hd: 'example.com' },
    updatedAt: iso(3 * 86400_000),
  }),
  view({
    id: 'apple',
    name: 'Apple',
    icon: dot('#111111'),
    issuer: 'https://id.example.net',
    clientId: 'org.example.pds',
    clientAuth: { method: 'client_secret_post', secret: null, key: { stored: 'wrapped' }, keyId: 'ABC123', signedSecret: { issuer: 'TEAMID', lifetimeSecs: 3600 } },
    responseMode: 'form_post',
    updatedAt: iso(26 * 3600_000),
  }),
  view({
    id: 'work',
    name: 'Example Corp',
    issuer: 'https://login.example.org/tenant/v2.0',
    clientId: 'a1b2c3',
    clientAuth: { method: 'private_key_jwt', secret: null, key: { stored: 'wrapped' }, keyId: 'k-2026', signedSecret: null },
    signup: 'invite',
    signupsPerDay: 25,
    trustEmail: true,
    idTokenAlgs: ['RS256', 'ES256'],
    updatedBy: 'sam',
    updatedAt: iso(4 * 3600_000),
  }),
]

const low = env('VLPDS_MOCK_LEVEL') === '1'
let providers = low ? [] : seed()
let version = low ? 0 : 7

const stored = (i) => (i ? { stored: 'wrapped' } : undefined)

const identities = {
  identities: [
    { ref: 'fed:0123456789abcdef01234567', issuer: 'https://accounts.example.com', provider: 'google', providerName: 'Google', display: 'alice@example.com', addedAt: iso(40 * 86400_000), lastUsedAt: iso(2 * 3600_000), dormant: false },
    { ref: 'fed:89abcdef0123456789abcdef', issuer: 'https://id.example.net', provider: 'apple', providerName: 'Apple', display: null, addedAt: iso(12 * 86400_000), lastUsedAt: null, dormant: false },
    { ref: 'fed:fedcba9876543210fedcba98', issuer: 'https://old.example.org', provider: null, providerName: null, display: 'alice@old.example.org', addedAt: iso(200 * 86400_000), lastUsedAt: iso(90 * 86400_000), dormant: true },
  ],
  providers: [
    { id: 'google', name: 'Google', icon: dot('#4285f4') },
    { id: 'apple', name: 'Apple', icon: dot('#111111') },
  ],
  available: true,
  max: 10,
  manageUrl: '/oauth/account',
}

const nodeList = () => [
  { node: 'node-a', ok: true },
  { node: 'node-b', ok: true },
  { node: 'node-c', ok: !low && providers.length !== 2, error: 'timed out' },
]

// listSessions for stream.place, TOKIMEKI Poll, Blacksky and Graysky (testdata/oauth), rows as
// the server computes them: regenerate with VLPDS_ROLLUP_DUMP=<dir> cargo test --lib
// oauth::rollup::tests::dump_rows and copy <dir>/oauth-sessions.json here.
const days = 86400_000
const oauthSessions = JSON.parse(readFileSync(new URL('./oauth-sessions.json', import.meta.url), 'utf8')).map((x, i) => ({
  id: `ses-mock${i}`,
  ...x,
  createdAt: iso([13, 3, 54, 30][i] * days),
  updatedAt: iso([0.1, 3, 1, 6][i] * days),
  accessExpiresAt: iso(-days / 24),
}))

let mockTicket = 1
const fail = (status, error, message) => ({ status, body: { error, message } })

function handle(nsid, body, method) {
  switch (nsid) {
    case 'vlpds.admin.getSession':
      return { body: { auth: 'proxy', operator: 'operator@example.com' } }
    case 'vlpds.admin.getClusterStatus':
      return {
        body: {
          node: 'node-a', publicUrl: 'https://pds.example.com', log: 'a', logDurableOrdinal: 10, owned: [0], shards: 1, table: ['node-a'],
          nodes: [{ node: 'node-a', log: 'a', addr: '127.0.0.1:2620', writer: 1, expiresMs: now + 10000, self: true, reachable: true, leaseValid: true }],
          leaseValid: true, firehose: { lastEmitted: '0', minWatermark: null, sources: [] }, fencedLogs: {}, time: Date.now(),
          version: { active: low ? 1 : 2, target: null, history: [], binary: { min: 1, max: 2, rev: 'abc1234' }, mixedBuilds: false, revs: ['abc1234'], finalizable: low ? 2 : null, finalizedAt: null },
        },
      }
    case 'vlpds.admin.listSignInProviders':
      return {
        body: {
          providers: low ? [] : providers, version, updatedAt: version ? iso(3600_000) : null, max: 20,
          featureLevel: { active: low ? 1 : 2, required: 2 }, available: !low, ...(low ? { reason: 'the cluster is below the required feature level' } : {}),
        },
      }
    case 'vlpds.admin.putSignInProvider': {
      const p = body.provider
      if (low) return fail(400, 'FeatureLevelRequired', 'sign-in providers need feature level 2')
      if (!/^[a-z0-9-]{1,32}$/.test(p.id)) return fail(400, 'InvalidProvider', `invalid id ${JSON.stringify(p.id)}`)
      const prev = providers.find((x) => x.id === p.id)
      if (prev && (prev.issuer !== p.issuer || prev.clientAuth.method !== p.clientAuth.method) && !p.clientAuth.secret && !p.clientAuth.key)
        return fail(400, 'InvalidProvider', 'changing the issuer or client auth method needs the secret or key again')
      if (body.ifVersion !== undefined && body.ifVersion !== version) return fail(409, 'VersionMismatch', `providers are at v${version}`)
      if (/unreachable/.test(p.issuer) && !body.force) return fail(400, 'ProviderUnreachable', `couldn't fetch ${p.issuer}/.well-known/openid-configuration`)
      const old = providers.find((x) => x.id === p.id)
      const a = p.clientAuth
      const next = view({
        ...p,
        icon: p.icon ?? null,
        clientAuth: {
          method: a.method,
          secret: a.secret ? stored(a.secret) : a.method === 'private_key_jwt' ? null : (old?.clientAuth.secret ?? null),
          key: a.key ? stored(a.key) : (old?.clientAuth.key ?? null),
          keyId: a.keyId ?? null,
          signedSecret: a.signedSecret ?? null,
        },
        scopes: p.scopes ?? ['openid', 'email'],
        signupsPerDay: p.signupsPerDay ?? 100,
        updatedAt: new Date().toISOString(),
        updatedBy: body.actor ?? 'operator',
      })
      providers = old ? providers.map((x) => (x.id === p.id ? next : x)) : [...providers, next]
      version += 1
      return { body: { provider: next, version, nodes: nodeList() } }
    }
    case 'vlpds.admin.removeSignInProvider':
      if (low) return fail(400, 'FeatureLevelRequired', 'sign-in providers need feature level 2')
      if (!providers.some((x) => x.id === body.id)) return fail(400, 'ProviderNotFound', `no provider ${body.id}`)
      providers = providers.filter((x) => x.id !== body.id)
      version += 1
      return { body: { id: body.id, version, nodes: nodeList() } }
    case 'vlpds.server.describeSignInProviders':
      return { body: { providers: low ? [] : providers.map((p) => ({ id: p.id, name: p.name, icon: p.icon })) } }
    case 'vlpds.server.createFederatedSession':
      if (method !== 'POST' || mockTicket-- <= 0) return fail(401, 'AuthenticationRequired', 'nothing to pick up')
      return { body: { did: 'did:plc:mock', handle: 'alice.example.com', email: 'alice@example.com', emailConfirmed: true, accessJwt: 'mock', refreshJwt: 'mock' } }
    case 'vlpds.server.listFederatedIdentities':
      return { body: low ? { ...identities, identities: [], available: false } : identities }
    case 'com.atproto.server.getSession':
      return { body: { did: 'did:plc:mock', handle: 'alice.example.com', email: 'alice@example.com', emailConfirmed: true, active: true } }
    case 'vlpds.server.getTotpStatus':
      return { body: { enabled: false, pending: false, recoveryCodesRemaining: 0 } }
    case 'vlpds.server.listPasskeys':
      return { body: { passkeys: [] } }
    case 'com.atproto.server.listAppPasswords':
      return { body: { passwords: [] } }
    case 'vlpds.oauth.listSessions':
      return { body: { sessions: oauthSessions } }
    case 'vlpds.server.getSignInSecurity':
      return { body: { oauthOnly: false, blockAppPasswords: false, alerts: { password: true, appPassword: true }, alertsPerDay: 5, secondFactor: false, trustDays: 30, trustedBrowsers: [], recentSignIns: [] } }
    default:
      return fail(404, 'MethodNotImplemented', `mock has no ${nsid}`)
  }
}

// VLPDS_MOCK_BRAND=<dir>: the branding `VLPDS_BRAND_DUMP=<dir> cargo test --lib brand::tests::dump_brand`
// wrote, in the head (as the server renders it) and at /brand/*.
const brandDir = env('VLPDS_MOCK_BRAND')
const DEFAULT_ICON = '<link rel="icon" type="image/svg+xml" href="/favicon.svg" />'

export function vlpdsMock() {
  return {
    name: 'vlpds-mock',
    apply: 'serve',
    transformIndexHtml(html, ctx) {
      if (env('VLPDS_MOCK') !== '1' || !brandDir) return html
      const path = ctx.originalUrl ?? ctx.path ?? '/'
      if (path.startsWith('/admin') || path.startsWith('/docs')) return html
      return html.replace(DEFAULT_ICON, readFileSync(join(brandDir, 'brand', 'head.txt'), 'utf8'))
    },
    configureServer(server) {
      if (env('VLPDS_MOCK') !== '1') return
      if (brandDir)
        server.middlewares.use('/brand', (req, res) => {
          const name = (req.url ?? '').split('?')[0].replace(/^\//, '')
          const types = { logo: 'image/png', favicon: 'image/png', 'brand.css': 'text/css' }
          if (!types[name]) return ((res.statusCode = 404), res.end())
          res.setHeader('content-type', types[name])
          res.end(readFileSync(join(brandDir, 'brand', name)))
        })
      server.middlewares.use('/xrpc', (req, res) => {
        const nsid = (req.url ?? '').split('?')[0].replace(/^\//, '')
        let raw = ''
        req.on('data', (c) => (raw += c))
        req.on('end', () => {
          let body = {}
          try {
            body = raw ? JSON.parse(raw) : {}
          } catch {
            /* no body */
          }
          const r = handle(nsid, body, req.method)
          res.statusCode = r.status ?? 200
          res.setHeader('content-type', 'application/json')
          res.end(JSON.stringify(r.body))
        })
      })
    },
  }
}
