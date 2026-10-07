// XRPC client for the account app (session JWTs) and the operator console
// (Basic admin:<token>, or nothing when a proxy in front of the admin listener
// names the operator). Both live in sessionStorage: they survive a reload but
// not a closed tab.

export class XrpcError extends Error {
  status: number
  error: string
  constructor(status: number, error: string, message: string) {
    super(message || error)
    this.status = status
    this.error = error
  }
}

export type Session = {
  did: string
  handle: string
  accessJwt: string
  refreshJwt: string
  email?: string
  emailConfirmed?: boolean
  active?: boolean
  status?: string
}

type Params = Record<string, string | number | boolean | string[] | undefined | null>

export function qs(params?: Params): string {
  if (!params) return ''
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) v.forEach((x) => u.append(k, x))
    else u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

export async function parse(r: Response) {
  const text = await r.text()
  let body: any = undefined
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }
  if (!r.ok) {
    const err = typeof body === 'object' && body ? body : {}
    throw new XrpcError(r.status, err.error ?? `HTTP ${r.status}`, err.message ?? (typeof body === 'string' ? body : ''))
  }
  return body
}

/** `base`: another server's origin (the migration page's old PDS); default this one. */
export type CallOpts = { params?: Params; body?: unknown; auth?: string; raw?: boolean; method?: 'GET' | 'POST'; base?: string; signal?: AbortSignal }

export async function call<T = any>(nsid: string, o: CallOpts = {}): Promise<T> {
  const method = o.method ?? (o.body !== undefined ? 'POST' : 'GET')
  const headers: Record<string, string> = {}
  if (o.auth) headers.Authorization = o.auth
  if (o.body !== undefined) headers['Content-Type'] = 'application/json'
  const r = await fetch(`${o.base ?? ''}/xrpc/${nsid}${qs(o.params)}`, {
    method,
    headers,
    body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
    signal: o.signal,
  })
  if (o.raw) {
    if (!r.ok) await parse(r)
    return r as unknown as T
  }
  return parse(r)
}

// ---------------------------------------------------------------- session store

const SKEY = 'vlpds.session'
const listeners = new Set<() => void>()
let session: Session | null = load()

function load(): Session | null {
  try {
    const s = sessionStorage.getItem(SKEY)
    return s ? JSON.parse(s) : null
  } catch {
    return null
  }
}

export function getSession() {
  return session
}

export function setSession(s: Session | null) {
  session = s
  try {
    if (s) sessionStorage.setItem(SKEY, JSON.stringify(s))
    else sessionStorage.removeItem(SKEY)
  } catch {
    /* storage blocked: memory only */
  }
  listeners.forEach((l) => l())
}

export function subscribeSession(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

let refreshing: Promise<void> | null = null

function refresh(): Promise<void> {
  const s = session
  if (!s) return Promise.reject(new XrpcError(401, 'AuthenticationRequired', 'Signed out'))
  refreshing ??= (async () => {
    try {
      const out = await call('com.atproto.server.refreshSession', { method: 'POST', auth: `Bearer ${s.refreshJwt}` })
      setSession({ ...s, ...out })
    } catch (e) {
      setSession(null)
      throw e
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

const expired = (e: unknown) => e instanceof XrpcError && e.error === 'ExpiredToken'

/** An authenticated call as the signed-in account; refreshes once on expiry. */
export async function acall<T = any>(nsid: string, o: CallOpts = {}): Promise<T> {
  const s = session
  if (!s) throw new XrpcError(401, 'AuthenticationRequired', 'Sign in first')
  try {
    return await call<T>(nsid, { ...o, auth: `Bearer ${s.accessJwt}` })
  } catch (e) {
    if (!expired(e)) throw e
    await refresh()
    return call<T>(nsid, { ...o, auth: `Bearer ${session!.accessJwt}` })
  }
}

export async function signOut() {
  const s = session
  setSession(null)
  if (s) {
    try {
      await call('com.atproto.server.deleteSession', { method: 'POST', auth: `Bearer ${s.refreshJwt}` })
    } catch {
      /* already gone */
    }
  }
}

// ---------------------------------------------------------------- admin token

const AKEY = 'vlpds.admin'
let adminToken: string | null = (() => {
  try {
    return sessionStorage.getItem(AKEY)
  } catch {
    return null
  }
})()
const adminListeners = new Set<() => void>()

// The operator a proxy signed in (vlpds.admin.getSession said `proxy`). Memory only: the
// console asks again on load.
let adminOperator: string | null = null

export const getAdminToken = () => adminToken
export const getAdminOperator = () => adminOperator
/** What unlocks the console: the token, or a proxy's sign-in. */
export const getAdminUnlock = () => adminToken ?? (adminOperator ? `proxy:${adminOperator}` : null)

export function setAdminOperator(login: string | null) {
  adminOperator = login
  adminListeners.forEach((l) => l())
}

/** Headers for an admin call: the token's Basic auth, none behind a signing proxy, null when locked. */
export function adminHeaders(): Record<string, string> | null {
  if (adminToken) return { authorization: basic(adminToken) }
  return adminOperator ? {} : null
}

/** null also forgets a proxy's sign-in, so a 401 sends the console back to its gate. */
export function setAdminToken(t: string | null) {
  adminToken = t
  if (!t) adminOperator = null
  try {
    if (t) sessionStorage.setItem(AKEY, t)
    else sessionStorage.removeItem(AKEY)
  } catch {
    /* memory only */
  }
  adminListeners.forEach((l) => l())
}
export function subscribeAdmin(l: () => void) {
  adminListeners.add(l)
  return () => {
    adminListeners.delete(l)
  }
}

export const basic = (token: string) => `Basic ${btoa(`admin:${token}`)}`

export async function admin<T = any>(nsid: string, o: CallOpts = {}): Promise<T> {
  if (!adminHeaders()) throw new XrpcError(401, 'AuthenticationRequired', 'Enter the admin token')
  try {
    return await call<T>(nsid, { ...o, auth: adminToken ? basic(adminToken) : undefined })
  } catch (e) {
    if (e instanceof XrpcError && e.status === 401) setAdminToken(null)
    throw e
  }
}

export function errText(e: unknown): string {
  if (e instanceof XrpcError) {
    const friendly: Record<string, string> = {
      AuthFactorTokenRequired: 'Enter the code from your authenticator app.',
      InvalidToken: 'That code is not valid. Check it and try again.',
      ExpiredToken: 'That code has expired. Request a new one.',
      RateLimitExceeded: 'Too many attempts. Wait a few minutes and try again.',
    }
    return friendly[e.error] ?? e.message ?? e.error
  }
  if (e instanceof Error) return e.message
  return String(e)
}
