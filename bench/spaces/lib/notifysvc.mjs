// A syncing service's inbound side: a real did:plc whose
// `#atproto_space_syncer` entry points here (or at a fault proxy in front of
// here), so space hosts resolve and reach it like any registered service. It
// verifies each call's service auth (iss = the space's authority, aud = this
// service's id, lxm) against the authority's key from the PLC, records it,
// and hands notifyWrite / notifySpaceDeleted to listeners. It also answers
// managedspace.checkUserAccess as a managing app.
import http from 'node:http'
import { verifySignature } from '@atproto/crypto'
import { createServiceDid, signingKey } from './identity.mjs'
import { decodeJwt, spaceDidOf } from './space.mjs'

export class NotifyService {
  constructor(port, { publicPort } = {}) {
    this.port = port
    this.publicPort = publicPort ?? port
    this.calls = []
    this.listeners = new Set()
    this.authFailures = []
    this.access = () => false // checkUserAccess policy: (space, user, access, clientId) => bool
  }

  async start() {
    this.server = http.createServer((req, res) => this.handle(req, res))
    await new Promise((r) => this.server.listen(this.port, '127.0.0.1', r))
    const id = await createServiceDid('atproto_space_syncer', `http://localhost:${this.publicPort}`)
    this.did = id.did
    this.serviceRef = id.serviceRef
    return this
  }

  async stop() {
    this.server?.closeAllConnections?.()
    await new Promise((r) => this.server?.close(r) ?? r())
  }

  on(fn) {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  callsTo(lxm, space) {
    return this.calls.filter((c) => c.lxm === lxm && (!space || c.body?.space === space))
  }

  async verifyAuth(auth, lxm, space) {
    if (!auth?.startsWith('Bearer ')) return 'no bearer service auth'
    const jwt = auth.slice(7)
    let claims
    try {
      claims = decodeJwt(jwt)
    } catch {
      return 'malformed jwt'
    }
    const { payload } = claims
    const authority = space ? spaceDidOf(space) : undefined
    if (authority && payload.iss !== authority) return `iss ${payload.iss} is not the authority ${authority}`
    if (payload.aud !== this.serviceRef && payload.aud !== this.did) return `aud ${payload.aud} is not ${this.serviceRef}`
    if (payload.lxm !== lxm) return `lxm ${payload.lxm} is not ${lxm}`
    if (!(payload.exp * 1000 > Date.now() - 5000)) return 'expired'
    const [h, p, s] = jwt.split('.')
    try {
      const key = await signingKey(payload.iss)
      const ok = await verifySignature(key, new TextEncoder().encode(`${h}.${p}`), Buffer.from(s, 'base64url'))
      if (!ok) return 'bad signature'
    } catch (e) {
      return `signature check failed: ${e.message}`
    }
    return null
  }

  async handle(req, res) {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const raw = Buffer.concat(chunks).toString('utf8')
    const url = new URL(req.url, 'http://localhost')
    const lxm = url.pathname.replace(/^\/xrpc\//, '')
    let body
    try {
      body = raw ? JSON.parse(raw) : Object.fromEntries(url.searchParams)
    } catch {
      body = raw
    }
    const at = performance.now()
    const authErr = await this.verifyAuth(req.headers.authorization, lxm, body?.space)
    const call = { lxm, body, at, wall: Date.now(), authErr }
    this.calls.push(call)
    const reply = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(obj ?? {}))
    }
    if (authErr) {
      this.authFailures.push(call)
      return reply(401, { error: 'AuthRequired', message: authErr })
    }
    if (lxm === 'com.atproto.managedspace.checkUserAccess') {
      const ok = !!this.access(body.space, body.user, body.access, body.clientId)
      return reply(200, { authorized: ok })
    }
    for (const fn of this.listeners) {
      try {
        fn(call)
      } catch (e) {
        console.error('notify listener', e)
      }
    }
    reply(200, {})
  }
}
