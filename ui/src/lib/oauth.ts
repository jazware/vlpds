// The UI's own atproto OAuth client: a public client (this server's
// /oauth/client-metadata.json, or a loopback client on a plain-http dev
// host), PAR + PKCE + DPoP, against any PDS's authorization server.
//
// In-tree rather than @atproto/oauth-client-browser: that client checks, on
// every token answer, that the DID document still names the issuer's PDS.
// The migration signs in at the OLD PDS after the DID has moved here, so it
// would refuse exactly the session the Spaces copy needs; here the caller
// names the PDS (the one the DID document named when the move began) and
// the account, and the token's `sub` must be that account.
//
// The DPoP key is a non-extractable WebCrypto key in IndexedDB: script on
// this page can sign with it while the page is open, but nothing can copy
// it out, so a token lifted from storage is no use anywhere else. Tokens
// and the pending sign-in live in sessionStorage (this tab only).

import { qs, parse } from './xrpc'

export class OAuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message)
  }
}

// ---------------------------------------------------------------- encoding

const enc = new TextEncoder()

function b64u(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const random = (n: number) => b64u(crypto.getRandomValues(new Uint8Array(n)))

async function sha256(s: string): Promise<string> {
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s))))
}

// ---------------------------------------------------------------- keys (IndexedDB)

const DB = 'vlpds-oauth'
const KEYS = 'dpop-keys'

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1)
    r.onupgradeneeded = () => r.result.createObjectStore(KEYS)
    r.onsuccess = () => resolve(r.result)
    r.onerror = () => reject(new OAuthError('storage', 'This browser blocks the storage sign-in needs (IndexedDB). A private window can do that.'))
  })
}

async function keyOp<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const d = await db()
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(d.transaction(KEYS, mode).objectStore(KEYS))
      req.onsuccess = () => resolve(req.result as T)
      req.onerror = () => reject(req.error)
    })
  } finally {
    d.close()
  }
}

type StoredKey = { pair: CryptoKeyPair; at: number }

const putKey = (id: string, pair: CryptoKeyPair) => keyOp<void>('readwrite', (s) => s.put({ pair, at: Date.now() } satisfies StoredKey, id))
const getKey = (id: string) => keyOp<StoredKey | undefined>('readonly', (s) => s.get(id)).then((k) => k?.pair)
const delKey = (id: string) => keyOp<void>('readwrite', (s) => s.delete(id)).catch(() => undefined)

/** A tab closed mid sign-in (or before the step ended) leaves its key
 * behind with nothing to revoke it. Sessions here last minutes, so a key
 * a day old that this tab doesn't use is an orphan. */
const KEY_MAX_AGE = 24 * 3600_000

export async function sweepKeys(names: string[]) {
  const mine = new Set<string>()
  const pending = ssGet<Pending>(PKEY)
  if (pending) mine.add(pending.keyId)
  for (const n of names) {
    const s = ssGet<Stored>(SKEY(n))
    if (s) mine.add(s.keyId)
  }
  try {
    const all = await keyOp<IDBValidKey[]>('readonly', (s) => s.getAllKeys())
    for (const id of all) {
      if (typeof id !== 'string' || mine.has(id)) continue
      const k = await keyOp<StoredKey | undefined>('readonly', (s) => s.get(id))
      if (!k || typeof k.at !== 'number' || Date.now() - k.at > KEY_MAX_AGE) await delKey(id)
    }
  } catch {
    /* no IndexedDB: nothing was kept */
  }
}

async function newKey(): Promise<{ id: string; pair: CryptoKeyPair }> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])) as CryptoKeyPair
  const id = random(16)
  await putKey(id, pair)
  return { id, pair }
}

// ---------------------------------------------------------------- DPoP

/** The latest DPoP-Nonce per origin (the AS's and the PDS's may differ). */
const nonces = new Map<string, string>()

const jwks = new WeakMap<CryptoKey, Promise<JsonWebKey>>()
function publicJwk(k: CryptoKey): Promise<JsonWebKey> {
  let p = jwks.get(k)
  if (!p) {
    p = crypto.subtle.exportKey('jwk', k).then(({ kty, crv, x, y }) => ({ kty, crv, x, y }))
    jwks.set(k, p)
  }
  return p
}

async function proof(pair: CryptoKeyPair, method: string, url: string, accessToken?: string): Promise<string> {
  const u = new URL(url)
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: await publicJwk(pair.publicKey) }
  const nonce = nonces.get(u.origin)
  const payload = {
    jti: random(16),
    htm: method,
    htu: u.origin + u.pathname,
    iat: Math.floor(Date.now() / 1000),
    ...(nonce ? { nonce } : {}),
    ...(accessToken ? { ath: await sha256(accessToken) } : {}),
  }
  const input = `${b64u(enc.encode(JSON.stringify(header)))}.${b64u(enc.encode(JSON.stringify(payload)))}`
  // WebCrypto's ECDSA signature is r||s, which is what JWS ES256 wants
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, enc.encode(input))
  return `${input}.${b64u(new Uint8Array(sig))}`
}

function keepNonce(url: string, r: Response) {
  const n = r.headers.get('dpop-nonce')
  if (n) nonces.set(new URL(url).origin, n)
}

/** A form POST to the authorization server, once more with a fresh nonce if it asks. */
async function asPost(url: string, pair: CryptoKeyPair, form: Record<string, string>): Promise<any> {
  for (let i = 0; ; i++) {
    let r: Response
    try {
      r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: await proof(pair, 'POST', url) },
        body: new URLSearchParams(form),
      })
    } catch {
      throw new OAuthError('network', `Couldn't reach ${new URL(url).host}. Check your connection and retry.`)
    }
    keepNonce(url, r)
    const body = await r.json().catch(() => ({}))
    if (r.ok) return body
    if (body.error === 'use_dpop_nonce' && i === 0) continue
    throw new OAuthError(body.error ?? `http_${r.status}`, body.error_description ?? `${new URL(url).host} answered ${r.status}`)
  }
}

// ---------------------------------------------------------------- discovery

export type AuthServer = {
  issuer: string
  par: string
  authorize: string
  token: string
  revoke?: string
}

async function getJson(url: string): Promise<any> {
  let r: Response
  try {
    r = await fetch(url, { redirect: 'error' })
  } catch {
    throw new OAuthError('network', `Couldn't reach ${new URL(url).host}. Check your connection and retry.`)
  }
  if (!r.ok) throw new OAuthError('discovery', `${new URL(url).host} has no OAuth metadata (${r.status}).`)
  return r.json()
}

/** Plain http only for the loopback dev client (a local stack). */
const httpOk = () => location.protocol === 'http:'

function url(v: unknown, what: string): URL {
  try {
    if (typeof v !== 'string') throw new Error()
    const u = new URL(v)
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && httpOk())) throw new Error()
    return u
  } catch {
    throw new OAuthError('discovery', `The server lists no usable ${what} (https only).`)
  }
}

function endpoint(name: string, v: unknown): string {
  return url(v, `${name} endpoint`).href
}

/** The PDS's authorization server, from its protected-resource metadata. */
export async function discover(pds: string): Promise<AuthServer> {
  const origin = new URL(pds).origin
  const pr = await getJson(`${origin}/.well-known/oauth-protected-resource`)
  // RFC 9728 §3.3: the metadata must name the server it came from
  if (url(pr.resource, 'resource').origin !== origin) throw new OAuthError('discovery', `${new URL(origin).host} names another server as itself.`)
  const issuer = pr.authorization_servers?.[0]
  const iss = url(issuer, 'authorization server')
  const m = await getJson(`${iss.origin}/.well-known/oauth-authorization-server`)
  // RFC 8414 §3.3: the metadata must be the issuer's own (mix-up attacks)
  if (m.issuer !== issuer) throw new OAuthError('discovery', `${issuer}'s metadata names another issuer.`)
  if (!(m.dpop_signing_alg_values_supported ?? []).includes('ES256')) throw new OAuthError('discovery', `${issuer} doesn't take ES256 DPoP proofs.`)
  return {
    issuer,
    par: endpoint('pushed authorization request', m.pushed_authorization_request_endpoint),
    authorize: endpoint('authorization', m.authorization_endpoint),
    token: endpoint('token', m.token_endpoint),
    revoke: m.revocation_endpoint ? endpoint('revocation', m.revocation_endpoint) : undefined,
  }
}

// ---------------------------------------------------------------- the client

/** Everything this client can ask for; /oauth/client-metadata.json lists the same. */
export const CLIENT_SCOPE =
  'atproto space:*?authority=*&action=read_self space:*?authority=*&collection=*&action=create&action=read_self blob:*/* space:*?action=read_self&manage=update&manage=delete space:*?manage=create&manage=update'

/** /migrate's redirect URI. */
export const CALLBACK_PATH = '/migrate/oauth/callback'
/** The account page's redirect URI (its "Your spaces" section). */
export const ACCOUNT_CALLBACK_PATH = '/account/oauth/callback'

export type ClientInfo = { clientId: string; redirectUri: string }

/** Null where no client can work: plain http on anything but 127.0.0.1 / [::1]. */
export function clientInfo(callback: string = CALLBACK_PATH): ClientInfo | null {
  const redirectUri = `${location.origin}${callback}`
  if (location.protocol === 'https:') return { clientId: `${location.origin}/oauth/client-metadata.json`, redirectUri }
  // RFC 8252 loopback: an atproto AS synthesizes the metadata from the id
  if (location.protocol === 'http:' && (location.hostname === '127.0.0.1' || location.hostname === '[::1]')) {
    return { clientId: `http://localhost?${new URLSearchParams({ redirect_uri: redirectUri, scope: CLIENT_SCOPE })}`, redirectUri }
  }
  return null
}

type Pending = {
  state: string
  verifier: string
  keyId: string
  server: AuthServer
  pds: string
  did: string
  scope: string
  name: string
  client: ClientInfo
  returnTo?: string
  at: number
}

type Stored = {
  name: string
  did: string
  pds: string
  server: AuthServer
  keyId: string
  scope: string
  access: string
  refresh?: string
  expiresAt: number
  client: ClientInfo
}

const PKEY = 'vlpds.oauth.pending'
const SKEY = (name: string) => `vlpds.oauth.session.${name}`
const PENDING_TTL = 15 * 60_000

function ssGet<T>(k: string): T | null {
  try {
    const s = sessionStorage.getItem(k)
    return s ? (JSON.parse(s) as T) : null
  } catch {
    return null
  }
}

function ssSet(k: string, v: unknown | null) {
  try {
    if (v === null) sessionStorage.removeItem(k)
    else sessionStorage.setItem(k, JSON.stringify(v))
  } catch {
    /* storage blocked: the sign-in can't survive its redirect */
  }
}

export type SignIn = {
  /** Which session this is ("old", "new"); a later sign-in under the name replaces it. */
  name: string
  /** The PDS to sign in at: its authorization server is discovered from it. */
  pds: string
  /** The account that must sign in; also the login hint. */
  did: string
  scope: string
  /** The redirect URI's path: {@link CALLBACK_PATH} unless given. */
  callback?: string
  /** Where the callback leaves the address bar (the callback page's area by default). */
  returnTo?: string
}

/** Starts a sign-in: PAR, then the browser goes to the authorization page
 * and comes back to the callback. Doesn't return when it works. */
export async function beginSignIn(s: SignIn): Promise<void> {
  const client = clientInfo(s.callback)
  if (!client) throw new OAuthError('unsupported', 'Signing in with OAuth needs this page on https (or http://127.0.0.1 for development).')
  const server = await discover(s.pds)
  const { id: keyId, pair } = await newKey()
  try {
    const verifier = random(32)
    const state = random(16)
    const par = await asPost(server.par, pair, {
      client_id: client.clientId,
      response_type: 'code',
      // the code comes back in the fragment: never sent to a server or in a Referer
      response_mode: 'fragment',
      redirect_uri: client.redirectUri,
      scope: s.scope,
      state,
      code_challenge: await sha256(verifier),
      code_challenge_method: 'S256',
      login_hint: s.did,
    })
    if (typeof par.request_uri !== 'string') throw new OAuthError('par', `${server.issuer} returned no request_uri.`)
    const old = ssGet<Pending>(PKEY)
    if (old) await delKey(old.keyId)
    ssSet(PKEY, { name: s.name, pds: s.pds, did: s.did, scope: s.scope, returnTo: s.returnTo, state, verifier, keyId, server, client, at: Date.now() } satisfies Pending)
    location.assign(`${server.authorize}${qs({ client_id: client.clientId, request_uri: par.request_uri })}`)
  } catch (e) {
    await delKey(keyId)
    throw e
  }
}

/** Whether this page load is the authorization server sending the user back. */
export const isCallback = (callback: string = CALLBACK_PATH) => location.pathname === callback

/** On the callback: checks the answer against the pending sign-in, redeems
 * the code and keeps the session. Returns its name. `back` is where the
 * address bar goes when the sign-in named no `returnTo`. */
export async function finishSignIn(back = '/migrate'): Promise<string> {
  // the code only ever comes in the fragment (response_mode=fragment), which
  // no server sees; a query is read for an error and nothing else
  const q = new URLSearchParams(location.search)
  const p = location.hash.length > 1 ? new URLSearchParams(location.hash.slice(1)) : new URLSearchParams(q.has('error') ? { state: q.get('state') ?? '', iss: q.get('iss') ?? '', error: q.get('error')!, error_description: q.get('error_description') ?? '' } : {})
  const pending = ssGet<Pending>(PKEY)
  ssSet(PKEY, null)
  // the code is single-use, but it shouldn't sit in the address bar or history
  history.replaceState(null, '', pending?.returnTo?.startsWith('/') ? pending.returnTo : back)
  if (!pending || Date.now() - pending.at > PENDING_TTL) {
    if (pending) await delKey(pending.keyId)
    throw new OAuthError('no_pending', 'This sign-in expired or was started in another tab. Start it again.')
  }
  const fail = async (code: string, m: string) => {
    await delKey(pending.keyId)
    return new OAuthError(code, m)
  }
  if (p.get('state') !== pending.state) throw await fail('state', 'The sign-in answer does not match the sign-in this tab started. Start it again.')
  // RFC 9207: an answer from another server's authorization page (mix-up)
  if (p.get('iss') !== pending.server.issuer) throw await fail('iss', 'The sign-in answer came from the wrong server. Start it again.')
  const err = p.get('error')
  if (err) throw await fail(err, err === 'access_denied' ? 'The sign-in was cancelled.' : (p.get('error_description') ?? err))
  const code = p.get('code')
  if (!code) throw await fail('no_code', 'The sign-in answer has no code. Start it again.')
  const pair = await getKey(pending.keyId)
  if (!pair) throw await fail('storage', 'The sign-in key is gone (browser storage was cleared). Start it again.')
  const tok = await asPost(pending.server.token, pair, {
    grant_type: 'authorization_code',
    client_id: pending.client.clientId,
    redirect_uri: pending.client.redirectUri,
    code,
    code_verifier: pending.verifier,
  }).catch(async (e) => {
    await delKey(pending.keyId)
    throw e
  })
  const stored = await checkToken(tok, pending, pending.keyId)
  // a second grant (more scope) replaces the first: its tokens are revoked, not left live
  const prev = ssGet<Stored>(SKEY(pending.name))
  if (prev && prev.keyId !== stored.keyId) await drop(prev)
  ssSet(SKEY(pending.name), stored)
  return pending.name
}

async function checkToken(tok: any, s: { name: string; did: string; pds: string; server: AuthServer; client: ClientInfo }, keyId: string): Promise<Stored> {
  const bad = async (m: string) => {
    await delKey(keyId)
    return new OAuthError('token', m)
  }
  if (typeof tok.access_token !== 'string' || String(tok.token_type).toLowerCase() !== 'dpop') throw await bad('The server issued no DPoP-bound token.')
  if (tok.sub !== s.did) throw await bad(`Signed in as ${tok.sub ?? 'someone else'}, not ${s.did}. Sign in with that account.`)
  return {
    name: s.name,
    did: s.did,
    pds: new URL(s.pds).origin,
    server: s.server,
    keyId,
    scope: typeof tok.scope === 'string' ? tok.scope : '',
    access: tok.access_token,
    refresh: typeof tok.refresh_token === 'string' ? tok.refresh_token : undefined,
    expiresAt: Date.now() + (typeof tok.expires_in === 'number' ? tok.expires_in * 1000 : 5 * 60_000),
    client: s.client,
  }
}

function canonScope(v: string): string {
  const i = v.indexOf('?')
  return i < 0 ? v : `${v.slice(0, i)}?${v.slice(i + 1).split('&').sort().join('&')}`
}

export class OAuthSession {
  private constructor(
    private s: Stored,
    private pair: CryptoKeyPair,
  ) {}

  static async load(name: string, did: string, pds: string): Promise<OAuthSession | null> {
    const s = ssGet<Stored>(SKEY(name))
    if (!s || s.did !== did || s.pds !== new URL(pds).origin) return null
    const pair = await getKey(s.keyId).catch(() => undefined)
    if (!pair) {
      ssSet(SKEY(name), null)
      return null
    }
    return new OAuthSession(s, pair)
  }

  get did() {
    return this.s.did
  }

  get pds() {
    return this.s.pds
  }

  /** Whether the granted scope includes every one of `scope`'s values
   * (servers normalize a value's parameter order, and issue a space value
   * with no `authority`, which means `self`, naming the account). */
  grants(scope: string): boolean {
    const have = new Set(this.s.scope.split(' ').map(canonScope))
    const issued = (v: string) => (v.startsWith('space:') && !/[?&]authority=/.test(v) ? `${v.includes('?') ? v : `${v}?`}&authority=${this.s.did}`.replace('?&', '?') : v)
    return scope.split(' ').every((v) => have.has(canonScope(v)) || have.has(canonScope(issued(v))))
  }

  private refreshing?: Promise<void>

  private refresh(): Promise<void> {
    this.refreshing ??= (async () => {
      try {
        if (!this.s.refresh) throw new OAuthError('expired', 'The sign-in expired. Sign in again.')
        const tok = await asPost(this.s.server.token, this.pair, {
          grant_type: 'refresh_token',
          client_id: this.s.client.clientId,
          refresh_token: this.s.refresh,
        })
        this.s = await checkToken(tok, this.s, this.s.keyId)
        ssSet(SKEY(this.s.name), this.s)
      } catch (e) {
        if (e instanceof OAuthError && e.code !== 'network') await this.forget()
        throw e
      } finally {
        this.refreshing = undefined
      }
    })()
    return this.refreshing
  }

  /** A DPoP-authorized request to this session's PDS. */
  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const url = `${this.s.pds}${path}`
    const method = (init.method ?? 'GET').toUpperCase()
    if (this.s.expiresAt < Date.now() + 30_000 && this.s.refresh) await this.refresh()
    for (let i = 0; ; i++) {
      const headers = new Headers(init.headers)
      headers.set('Authorization', `DPoP ${this.s.access}`)
      headers.set('DPoP', await proof(this.pair, method, url, this.s.access))
      const r = await fetch(url, { ...init, method, headers })
      keepNonce(url, r)
      if (r.status !== 401 || i > 1) return r
      const www = r.headers.get('www-authenticate') ?? ''
      if (/use_dpop_nonce/.test(www)) continue
      if (/invalid_token/.test(www) && this.s.refresh) {
        await this.refresh()
        continue
      }
      return r
    }
  }

  /** An XRPC call; a refusal throws the server's XrpcError. */
  async call<T = any>(nsid: string, o: { params?: Record<string, string | number | undefined>; body?: BodyInit; type?: string; raw?: boolean } = {}): Promise<T> {
    let r: Response
    try {
      r = await this.fetch(`/xrpc/${nsid}${qs(o.params)}`, {
        method: o.body !== undefined ? 'POST' : 'GET',
        headers: o.type ? { 'Content-Type': o.type } : undefined,
        body: o.body,
      })
    } catch (e) {
      if (e instanceof OAuthError) throw e
      throw new Error(`Couldn't reach ${new URL(this.s.pds).host}. Check your connection and retry.`)
    }
    if (o.raw) {
      if (!r.ok) await parse(r)
      return r as unknown as T
    }
    return parse(r)
  }

  /** Revokes the tokens (best effort) and drops the key and the session. */
  forget(): Promise<void> {
    return drop(this.s)
  }
}

async function drop(s: Stored) {
  ssSet(SKEY(s.name), null)
  if (s.server.revoke) {
    await fetch(s.server.revoke, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: s.client.clientId, token: s.refresh ?? s.access }),
    }).catch(() => undefined)
  }
  await delKey(s.keyId)
}

/** Drops (and revokes) the named sessions this tab holds, and a pending sign-in for one of them. */
export async function forgetAll(names: string[]) {
  const pending = ssGet<Pending>(PKEY)
  if (pending && names.includes(pending.name)) {
    ssSet(PKEY, null)
    await delKey(pending.keyId)
  }
  for (const n of names) {
    const s = ssGet<Stored>(SKEY(n))
    if (s) await drop(s)
  }
}
