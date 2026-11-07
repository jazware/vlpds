// The account page's "Your spaces" section: its OAuth session (this
// server's own client, apart from the password session the rest of /account
// uses) and the reads it makes with it.

import { useEffect, useState, useSyncExternalStore } from 'react'
import { ACCOUNT_CALLBACK_PATH, beginSignIn, finishSignIn, forgetAll, OAuthSession, sweepKeys } from './oauth'
import { call, XrpcError } from './xrpc'

export const SESSION = 'spaces'
/** Reads the user's own space repos, and the spaces they govern (getSpace and listMembers are owner reads). */
export const READ_SCOPE = 'atproto space:*?authority=*&action=read_self'
/** Members and deletion, only for spaces this account governs (`authority` defaults to `self`). */
export const OWNER_SCOPE = 'space:*?action=read_self&manage=update&manage=delete'

// ---------------------------------------------------------------- the session

type State = { session: OAuthSession | null; loading: boolean; error?: unknown }
let state: State = { session: null, loading: true }
const listeners = new Set<() => void>()
const set = (s: State) => {
  state = s
  listeners.forEach((l) => l())
}

let loadedFor: string | undefined
let loading: Promise<void> | undefined

/** Loads the stored session once per account; one for another account is revoked. */
function load(did: string) {
  if (loadedFor === did) return loading
  loadedFor = did
  loading = (async () => {
    await callback
    const s = await OAuthSession.load(SESSION, did, location.origin).catch(() => null)
    // one kept for another account (or whose key is gone) is no use: revoke it
    if (!s && holdsSession()) await forgetAll([SESSION])
    void sweepKeys([SESSION])
    set({ session: s, loading: false, error: callbackError })
  })()
  return loading
}

export function useSpacesSession(did: string): State {
  const s = useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => state,
  )
  useEffect(() => {
    void load(did)
  }, [did])
  return s
}

let callback: Promise<void> | undefined
let callbackError: unknown

/** On {@link ACCOUNT_CALLBACK_PATH}: redeems the code (once, however often it's called). */
export function finishCallback(): Promise<void> {
  callback ??= finishSignIn('/account/spaces')
    .then(() => undefined)
    .catch((e) => {
      callbackError = e
    })
    .finally(() => {
      loadedFor = undefined
    })
  return callback
}

export function connect(did: string, scope: string, returnTo: string) {
  return beginSignIn({ name: SESSION, pds: location.origin, did, scope, callback: ACCOUNT_CALLBACK_PATH, returnTo })
}

/** Revokes the section's tokens and deletes its key: sign-out, and leaving the section. */
export async function disconnect() {
  const had = state.session
  callbackError = undefined
  if (had) set({ session: null, loading: false })
  await forgetAll([SESSION])
}

/** Whether this tab holds the section's session (without loading it). */
export function holdsSession(): boolean {
  try {
    return sessionStorage.getItem(`vlpds.oauth.session.${SESSION}`) !== null
  } catch {
    return false
  }
}

// ---------------------------------------------------------------- spaces

export type SpaceRef = { uri: string; authority: string; type: string; skey: string }

export function parseSpace(uri: string): SpaceRef | null {
  const m = /^at:\/\/([^/]+)\/space\/([^/]+)\/([^/]+)$/.exec(uri)
  return m ? { uri, authority: m[1], type: m[2], skey: m[3] } : null
}

export const spaceUri = (authority: string, type: string, skey: string) => `at://${authority}/space/${type}/${skey}`
export const spacePath = (s: SpaceRef) => `/account/spaces/${encodeURIComponent(s.authority)}/${s.type}/${encodeURIComponent(s.skey)}`

const S32 = '234567abcdefghijklmnopqrstuvwxyz'

/** A TID's time (a rev is one), in ms. */
export function tidTime(tid?: string): number | undefined {
  if (!tid || !/^[2-7a-z]{13}$/.test(tid)) return undefined
  let v = 0n
  for (const c of tid) v = v * 32n + BigInt(S32.indexOf(c))
  return Number((v >> 10n) / 1000n)
}

/** Every space the account writes in or governs (listSpaces). */
export async function listSpaces(s: OAuthSession): Promise<SpaceRef[]> {
  const out: SpaceRef[] = []
  for (let cursor: string | undefined, i = 0; i < 50; i++) {
    const r = await s.call('com.atproto.space.listSpaces', { params: { limit: 100, cursor } })
    for (const x of r.spaces ?? []) {
      const p = parseSpace(x.uri)
      if (p) out.push(p)
    }
    if (!r.cursor || !(r.spaces ?? []).length) break
    cursor = r.cursor
  }
  return out
}

/** Pages of a record count before it's shown as "N+". */
const COUNT_PAGES = 10
const COUNT_PAGE = 1000

export type MyRepo = { records: number; more: boolean; rev?: string; lastWrite?: number }

/** The account's own repo in `space`: null when it never wrote there. */
export async function myRepo(s: OAuthSession, space: string): Promise<MyRepo | null> {
  let rev: string | undefined
  try {
    const c = await s.call('com.atproto.space.getLatestCommit', { params: { space, repo: s.did } })
    rev = c.commit?.rev
  } catch (e) {
    if (e instanceof XrpcError && e.error === 'RepoNotFound') return null
    throw e
  }
  let records = 0
  let more = false
  for (let cursor: string | undefined, i = 0; ; i++) {
    if (i === COUNT_PAGES) {
      more = true
      break
    }
    const r = await s.call('com.atproto.space.listRecords', { params: { space, repo: s.did, limit: COUNT_PAGE, cursor, excludeValues: 'true' } })
    records += (r.records ?? []).length
    if (!r.cursor) break
    cursor = r.cursor
  }
  return { records, more, rev, lastWrite: tidTime(rev) }
}

export type Policy = {
  $type: string
  publicRead?: boolean
  publicWrite?: boolean
  allowedApps?: string[]
  managingApp?: string
  publishPolicy?: boolean
  publishMembers?: boolean
}
export type Member = { did: string; read: boolean; write: boolean }
export type Governance = { policy: Policy; members: Member[]; more: boolean }

export const MEMBERSPACE = 'com.atproto.memberspace.policy'
export const MANAGEDSPACE = 'com.atproto.managedspace.policy'
export const PERSONALSPACE = 'com.atproto.personalspace.policy'

const MEMBER_PAGES = 10

/** A space the account governs: its policy and, for a memberspace, its members. */
export async function governance(s: OAuthSession, space: string): Promise<Governance> {
  const g = await s.call('com.atproto.space.getSpace', { params: { space } })
  const policy: Policy = g.policy
  const members: Member[] = []
  let more = false
  for (let cursor: string | undefined, i = 0; policy.$type === MEMBERSPACE; i++) {
    if (i === MEMBER_PAGES) {
      more = true
      break
    }
    const r = await s.call('com.atproto.memberspace.listMembers', { params: { space, limit: 1000, cursor } })
    members.push(...(r.members ?? []))
    if (!r.cursor || !(r.members ?? []).length) break
    cursor = r.cursor
  }
  return { policy, members, more }
}

/** Who may read (or write) under `p`, besides the owner. */
export function accessText(p: Policy | undefined, side: 'read' | 'write'): string {
  switch (p?.$type) {
    case PERSONALSPACE:
      return 'only you'
    case MEMBERSPACE:
      return (side === 'read' ? p.publicRead : p.publicWrite) ? 'anyone' : 'members'
    case MANAGEDSPACE:
      return 'an app decides'
    default:
      return p?.$type ?? '—'
  }
}

/** Runs `fn` over `xs`, `n` at a time. */
export async function pool<T, R>(xs: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(xs.length)
  let next = 0
  await Promise.all(
    Array.from({ length: Math.min(n, xs.length) }, async () => {
      while (next < xs.length) {
        const i = next++
        out[i] = await fn(xs[i])
      }
    }),
  )
  return out
}

// ---------------------------------------------------------------- identities

export type Identity = { did: string; handle?: string }

const ids = new Map<string, Promise<Identity>>()

/** A DID's handle, only when the handle resolves back to it (else none). */
export function identity(did: string): Promise<Identity> {
  let p = ids.get(did)
  if (!p) {
    p = call('com.atproto.identity.resolveIdentity', { params: { identifier: did } })
      .then((r) => ({ did, handle: r.did === did && r.handle && r.handle !== 'handle.invalid' ? r.handle : undefined }))
      .catch(() => ({ did }))
    ids.set(did, p)
  }
  return p
}

export function useIdentity(did: string): Identity {
  const [v, setV] = useState<Identity>({ did })
  useEffect(() => {
    let live = true
    identity(did).then((x) => live && setV(x))
    return () => {
      live = false
    }
  }, [did])
  return v
}

/** A handle (or DID) typed in: its DID, only when the handle verifies both ways. */
export async function resolveMember(input: string): Promise<{ did: string; handle?: string }> {
  const id = input.trim().replace(/^@/, '')
  if (!id) throw new Error('Enter a handle.')
  let r: any
  try {
    r = await call('com.atproto.identity.resolveIdentity', { params: { identifier: id } })
  } catch (e) {
    if (e instanceof XrpcError && /NotFound|InvalidRequest/.test(e.error)) throw new Error(`Couldn't find ${id}. Check the spelling.`)
    throw e
  }
  if (id.startsWith('did:')) return { did: r.did, handle: r.handle !== 'handle.invalid' ? r.handle : undefined }
  if (r.handle === 'handle.invalid' || r.handle?.toLowerCase() !== id.toLowerCase())
    throw new Error(`${id} points to ${r.did}, but that account doesn't claim the handle back, so it can't be trusted. Use the DID if you're sure.`)
  ids.set(r.did, Promise.resolve({ did: r.did, handle: r.handle }))
  return { did: r.did, handle: r.handle }
}
