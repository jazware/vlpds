// The migration's Spaces step: the space repos the account writes, copied
// from the old PDS to this one once the account is live here. Space data is
// OAuth-only on both sides, so each side gets its own OAuth sign-in with
// only what its half needs: reading the account's own space repos there,
// importing them (and, when they name any, uploading blobs) here.

import { OAuthSession } from '../../lib/oauth'
import { XrpcError } from '../../lib/xrpc'
import { retry } from '../../lib/backoff'

export const OLD_SCOPE = 'atproto space:*?authority=*&action=read_self'
export const NEW_SCOPE = 'atproto space:*?authority=*&collection=*&action=create&action=read_self&manage=create&manage=update'
export const BLOB_SCOPE = 'blob:*/*'

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

export type SpacePlan = { uri: string; blobs: string[]; empty: boolean }

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
    out.push({ uri, blobs, empty })
  }
  return out
}

/** Plain words for the reasons an import is refused. */
export function reasonOf(e: unknown): string {
  if (e instanceof XrpcError) {
    const known: Record<string, string> = {
      InvalidCommit: "its signature doesn't match any key your account has held",
      DigestMismatch: "the copy doesn't add up to what was signed",
      NotAuthorized: "the space's owner no longer lets you write there",
      SpaceNotFound: 'the space no longer exists',
      SpaceDeleted: 'the space was deleted',
      UnsupportedPolicy: "this server doesn't support the space's policy",
      FutureRev: "its last change is dated in the future; check your device's clock and the old server's",
      RepoTooLarge: 'it is larger than this server takes',
      ScopeMissing: "the sign-in here didn't grant what the copy needs; sign in again and allow everything asked",
    }
    return known[e.error] ?? (e.message || e.error)
  }
  return e instanceof Error ? e.message : String(e)
}

/** A space the account governs: its policy, members and writer set, from
 * the old server's exportSpaceMeta to importSpaceMeta here, before its
 * repo (October 29 alpha). An old server from before it has none to give:
 * the space then arrives as it did before, with the repo alone. */
async function copySpaceMeta(old: OAuthSession, here: OAuthSession, uri: string, onPause: (until: number) => void): Promise<void> {
  if (spaceLabel(uri).authority !== old.did) return
  let meta: Blob
  try {
    meta = await retry(
      () => old.call<Response>('com.atproto.space.exportSpaceMeta', { params: { space: uri }, raw: true }).then((r) => r.blob()),
      onPause,
    )
  } catch (e) {
    if (e instanceof XrpcError && (e.error === 'MethodNotImplemented' || e.status === 404 || e.status === 501)) return
    throw e
  }
  await retry(() => here.call('com.atproto.space.importSpaceMeta', { body: meta, type: 'application/octet-stream' }), onPause)
}

/** The space's meta when the account governs it, then the old server's
 * getRepo, then importRepo here (a retried import of the same rev is
 * accepted as is), then any blobs its records name. */
export async function copySpace(
  old: OAuthSession,
  here: OAuthSession,
  p: SpacePlan,
  onPause: (until: number) => void,
  onBlob: (done: number) => void,
): Promise<SpaceMove> {
  await copySpaceMeta(old, here, p.uri, onPause)
  if (p.empty) return { uri: p.uri, state: 'empty' }
  // a STAR archive (the October 22 alpha), passed on as is
  let archive: Blob
  try {
    archive = await retry(
      () => old.call<Response>('com.atproto.space.getRepo', { params: { space: p.uri, repo: old.did }, raw: true }).then((r) => r.blob()),
      onPause,
    )
  } catch (e) {
    if (notFound(e)) return { uri: p.uri, state: 'empty' }
    throw e
  }
  const out = await retry(() => here.call('vlpds.space.importRepo', { params: { space: p.uri }, body: archive, type: 'application/octet-stream' }), onPause)
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
  return { uri: p.uri, state: 'moved', records: typeof out?.records === 'number' ? out.records : undefined, blobs: n }
}

/** "com.example.forum" in "at://did:plc:…/space/com.example.forum/main", and its key. */
export function spaceLabel(uri: string): { type: string; skey: string; authority: string } {
  const [, , authority = '', , type = '', skey = ''] = uri.split('/')
  return { type, skey, authority }
}
