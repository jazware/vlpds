// Pluggable owner authentication, from the browser's side.
//
// One small client for both frontends' shared wire contract: which methods a
// server runs, starting a login, answering a challenge (a wallet signature,
// or the account fields for a new identity), and redeeming the finished
// login for an ordinary session. The server decides when a login is done —
// nothing here sets a session except `redeem`.

import { parse, XrpcError, type Session } from './xrpc'

/** A configured method. `presentation` is how the browser runs its proof. */
export type Provider = { id: string; label: string; presentation: 'redirect' | 'siwe' }

/** What the browser must do next, from `/auth/start` or `/auth/link`. */
export type Challenge =
  | { kind: 'redirect'; url: string }
  | { kind: 'siwe'; message: string; address?: string }

export type Started = { txnId: string; provider: string; challenge: Challenge }

/** `/auth/continue`'s answer: what the login needs, or that it is done. */
export type Progress =
  | { status: 'done'; did: string; handle: string }
  | { status: 'signup'; txnId: string; provider: string; email?: string }
  | { status: 'factor'; url: string }
  | { status: 'linked'; credential: Credential }
  | { status: 'confirmed'; grant: string }

export type Credential = {
  id: string
  provider: string
  label?: string | null
  createdAt: number
  lastUsedAt?: number | null
}

async function request<T>(path: string, body: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (token) headers.authorization = `Bearer ${token}`
  const r = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body) })
  return parse(r) as Promise<T>
}

/** The methods this server runs. Never enumerates accounts. */
export async function methods(): Promise<Provider[]> {
  const r = await fetch('/auth/methods')
  const j = (await parse(r)) as { providers?: Provider[] }
  return j.providers ?? []
}

/** Begin signing in (or signing up) with a method. */
export function start(provider: string, intent: 'sign_in' | 'sign_up', address?: string): Promise<Started> {
  return request<Started>('/auth/start', { provider, intent, address })
}

/** Begin linking a method to the signed-in account. A password account
 * confirms with `password`; a provider-only account confirms with a `grant`
 * from `/auth/reauth`. */
export function link(
  provider: string,
  opts: { token: string; address?: string; password?: string; grant?: string },
): Promise<Started> {
  return request<Started>(
    '/auth/link',
    { provider, address: opts.address, password: opts.password, grant: opts.grant },
    opts.token,
  )
}

/** Begin a fresh proof of ownership before a sensitive change. */
export function reauth(
  provider: string,
  action: string,
  target: string,
  opts: { token: string; address?: string },
): Promise<Started> {
  return request<Started>('/auth/reauth', { provider, action, target, address: opts.address }, opts.token)
}

/** Answer a challenge, collect account fields, attach a credential, or
 * confirm an operation. The server validates everything. */
export function proceed(body: Record<string, unknown>): Promise<Progress> {
  return request<Progress>('/auth/continue', body)
}

/** Redeem a finished login on this browser for an ordinary session. Null when
 * this browser has no completed sign-in. */
export async function redeem(): Promise<Session | null> {
  try {
    return await request<Session>('/auth/complete', {})
  } catch (e) {
    if (e instanceof XrpcError && (e.status === 401 || e.error === 'AuthenticationRequired')) return null
    throw e
  }
}

/** EIP-1193, as wallets inject it: only the one call we make. */
type EthProvider = {
  request: (a: { method: string; params?: unknown[] }) => Promise<unknown>
}

// Wallets inject `window.ethereum`; the DOM lib does not declare it, and
// there is no runtime check to make — a page script could only replace the
// user's own wallet prompt.
const injectedWindow: Window & { ethereum?: EthProvider } = window

/** The wallet address to sign with, asking the wallet to reveal it. */
export async function walletAddress(): Promise<string> {
  const eth = injectedWindow.ethereum
  if (!eth) throw new Error('No Ethereum wallet is available in this browser.')
  const accounts = (await eth.request({ method: 'eth_requestAccounts' })) as string[]
  const address = accounts?.[0]
  if (!address) throw new Error('The wallet did not offer an account.')
  return address
}

/** Sign an EIP-4361 message with the wallet, returning the signature. */
export async function signMessage(message: string, address: string): Promise<string> {
  const eth = injectedWindow.ethereum
  if (!eth) throw new Error('No Ethereum wallet is available in this browser.')
  try {
    const sig = await eth.request({ method: 'personal_sign', params: [message, address] })
    if (typeof sig !== 'string') throw new Error('The wallet did not return a signature.')
    return sig
  } catch (e) {
    // EIP-1193 user rejection is 4001; the wording differs per wallet.
    const code = (e as { code?: number }).code
    if (code === 4001 || /reject|denied|cancel/i.test(String((e as Error)?.message ?? ''))) {
      throw new Error('The signature request was cancelled.')
    }
    throw e
  }
}