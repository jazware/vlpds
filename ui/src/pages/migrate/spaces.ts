// The migration's Spaces step: the spaces the account runs and the space
// repos it writes, copied from the old PDS to this one once the account is
// live here. Space data is OAuth-only on both sides, so each side gets its
// own OAuth sign-in with only what its half needs: reading the account's own
// spaces there, importing them (and, when they name any, uploading blobs)
// here. A space the account runs moves first (exportSpaceMeta there,
// importSpaceMeta here), since its owner's repo can't be imported before it.

import { OAuthSession } from '../../lib/oauth'
import { XrpcError } from '../../lib/xrpc'
import { retry } from '../../lib/backoff'

export const OLD_SCOPE = 'atproto space:*?authority=*&action=read_self'
export const NEW_SCOPE = 'atproto space:*?authority=*&collection=*&action=create&action=read_self'
export const BLOB_SCOPE = 'blob:*/*'
/** Importing the spaces the account runs (`authority` defaults to the account itself). */
export const GOVERN_SCOPE = 'space:*?manage=create&manage=update'

/** What the sign-in here needs for `plans`. */
export const newScope = (plans: SpacePlan[]) =>
  [NEW_SCOPE, plans.some((p) => p.governed) && GOVERN_SCOPE, plans.some((p) => p.blobs.length) && BLOB_SCOPE].filter(Boolean).join(' ')

/** Saved per space (no secrets), so a reload shows the outcome and retries only what didn't move. */
export type SpaceMove = {
  uri: string
  state: 'moved' | 'failed' | 'empty'
  records?: number
  blobs?: number
  reason?: string
}

/** Past these, a listing that keeps paging is broken (or hostile), not big:
 * a repo holds at most 100k records. */
const MAX_SPACES = 10_000
const MAX_BLOBS = 100_000

/** `governed`: the account is the space's authority, so the space itself moves too. */
export type SpacePlan = { uri: string; blobs: string[]; empty: boolean; governed: boolean }

/** Whether `base` serves Spaces at all: an unauthenticated listSpaces is
 * refused for want of auth there, and as an unknown method elsewhere. */
export async function servesSpaces(base: string): Promise<boolean> {
  let r: Response
  try {
    r = await fetch(`${base}/xrpc/com.atproto.space.listSpaces`)
  } catch {
    throw new Error(`Couldn't reach ${new URL(base, location.href).host}. Check your connection and retry.`)
  }
  if (r.status === 401) return true
  const body = await r.json().catch(() => ({}))
  return r.status === 400 && /^Auth/.test(body.error ?? '')
}

const notFound = (e: unknown) => e instanceof XrpcError && (e.error === 'RepoNotFound' || e.error === 'SpaceNotFound')

/** Every space the account holds a repo in (or governs) there, and each repo's blobs. */
export async function plan(old: OAuthSession, onPause: (until: number) => void): Promise<SpacePlan[]> {
  const uris: string[] = []
  const seen = new Set<string>()
  for (let cursor: string | undefined; ; ) {
    const page = await retry(() => old.call('com.atproto.space.listSpaces', { params: { limit: 100, cursor } }), onPause)
    for (const s of page.spaces as { uri: string }[]) uris.push(s.uri)
    if (uris.length > MAX_SPACES) throw new Error(`${new URL(old.pds).host} lists more than ${MAX_SPACES} spaces.`)
    cursor = page.cursor
    if (!cursor || !page.spaces.length || seen.has(cursor)) break
    seen.add(cursor)
  }
  const out: SpacePlan[] = []
  for (const uri of uris) {
    const blobs: string[] = []
    let empty = false
    try {
      const seen = new Set<string>()
      for (let cursor: string | undefined; ; ) {
        const page = await retry(() => old.call('com.atproto.space.listBlobs', { params: { space: uri, repo: old.did, limit: 1000, cursor } }), onPause)
        blobs.push(...(page.cids as string[]))
        if (blobs.length > MAX_BLOBS) throw new Error(`${new URL(old.pds).host} lists more than ${MAX_BLOBS} files in one space.`)
        cursor = page.cursor
        if (!cursor || !page.cids.length || seen.has(cursor)) break
        seen.add(cursor)
      }
    } catch (e) {
      // a space it governs but never wrote in: no repo to bring
      if (!notFound(e)) throw e
      empty = true
    }
    out.push({ uri, blobs, empty, governed: spaceLabel(uri).authority === old.did })
  }
  return out
}

/** Plain words for the reasons an import is refused. */
export function reasonOf(e: unknown): string {
  if (e instanceof XrpcError) {
    const known: Record<string, string> = {
      InvalidCommit: 'the copy is damaged',
      DigestMismatch: "the copy's records don't add up to its commit",
      UnsupportedPolicy: "this server doesn't support the space's access rules",
      NotSpaceOwner: "the space isn't yours to bring",
      NotAuthorized: "the space's owner no longer lets you write there",
      SpaceNotFound: 'the space no longer exists',
      SpaceDeleted: 'the space was deleted',
      FutureRev: "its last change is dated in the future; check your device's clock and the old server's",
      RepoTooLarge: 'it is larger than this server takes',
      ScopeMissing: "the sign-in here didn't grant what the copy needs; sign in again and allow everything asked",
    }
    return known[e.error] ?? (e.message || e.error)
  }
  return e instanceof Error ? e.message : String(e)
}

/** For a space the account runs, its meta first (exportSpaceMeta there,
 * importSpaceMeta here); then the old server's getRepo, importRepo here, and
 * any blobs its records name. Both imports replace what's here, so a retry
 * is safe. */
export async function copySpace(
  old: OAuthSession,
  here: OAuthSession,
  p: SpacePlan,
  onPause: (until: number) => void,
  onBlob: (done: number) => void,
): Promise<SpaceMove> {
  if (p.governed) {
    const meta = await retry(() => old.call<Response>('com.atproto.space.exportSpaceMeta', { params: { space: p.uri }, raw: true }).then((r) => r.blob()), onPause)
    await retry(() => here.call('com.atproto.space.importSpaceMeta', { body: meta, type: 'application/octet-stream' }), onPause)
  }
  if (p.empty) return p.governed ? { uri: p.uri, state: 'moved', records: 0, blobs: 0 } : { uri: p.uri, state: 'empty' }
  let star: Blob
  try {
    star = await retry(
      () => old.call<Response>('com.atproto.space.getRepo', { params: { space: p.uri, repo: old.did }, raw: true }).then((r) => r.blob()),
      onPause,
    )
  } catch (e) {
    if (notFound(e)) return p.governed ? { uri: p.uri, state: 'moved', records: 0, blobs: 0 } : { uri: p.uri, state: 'empty' }
    throw e
  }
  await retry(() => here.call('com.atproto.space.importRepo', { body: star, type: 'application/octet-stream' }), onPause)
  const records = starPairs(new Uint8Array(await star.arrayBuffer()))
  let n = 0
  for (const cid of p.blobs) {
    await retry(async () => {
      const r = await old.call<Response>('com.atproto.space.getBlob', { params: { space: p.uri, repo: old.did, cid }, raw: true })
      const type = r.headers.get('content-type') || 'application/octet-stream'
      const up = await here.call('com.atproto.repo.uploadBlob', { body: await r.blob(), type })
      const got = up?.blob?.ref?.$link
      if (got !== cid) throw new Error(`a file hashed to ${got ?? 'nothing'}, not ${cid}`)
    }, onPause)
    onBlob(++n)
  }
  return { uri: p.uri, state: 'moved', records, blobs: n }
}

/** The records in a getRepo archive (STAR: magic, metadata, then a 0x01
 * byte before each key/value pair and 0x00 at the end); undefined if it
 * doesn't parse, since the count is only shown. */
export function starPairs(b: Uint8Array): number | undefined {
  let i = 4
  const varint = () => {
    let v = 0
    for (let shift = 0; i < b.length; shift += 7) {
      const x = b[i++]
      v += (x & 0x7f) * 2 ** shift
      if (!(x & 0x80)) return v
    }
    return -1
  }
  const skip = () => {
    const n = varint()
    if (n < 0 || i + n > b.length) return false
    i += n
    return true
  }
  if (!skip()) return undefined
  for (let n = 0; i < b.length; n++) {
    if (b[i] === 0x00) return n
    if (b[i++] !== 0x01 || !skip() || !skip()) return undefined
  }
  return undefined
}

/** "com.example.forum" in "at://did:plc:…/space/com.example.forum/main", and its key. */
export function spaceLabel(uri: string): { type: string; skey: string; authority: string } {
  const [, , authority = '', , type = '', skey = ''] = uri.split('/')
  return { type, skey, authority }
}
