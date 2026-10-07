import { decode, decodeFirst, type TagDecoder } from 'cborg'
import { useSyncExternalStore } from 'react'
import { admin } from '../xrpc'
import { getLive } from './live'

// The live tail: this PDS's own com.atproto.sync.subscribeRepos over a websocket, decoded in
// the browser. Every node emits the whole merged stream, so the node serving the console is
// enough. While paused, frames keep arriving and wait in a buffer. The console shows up in the
// subscriber list as one more connection, without a cursor.

export type FhKind = 'commit' | 'identity' | 'account' | 'sync'
export type FhOp = { action: 'create' | 'update' | 'delete'; path: string; cid?: string }
export type FhEvent = {
  id: number
  seq: string
  kind: FhKind
  did: string
  /** When the frame arrived here. */
  at: number
  /** The event's own `time`. */
  time?: string
  ops: FhOp[]
  handle?: string
  active?: boolean
  status?: string
  rev?: string
  commit?: string
  blocksBytes?: number
  frameBytes: number
  body: Record<string, unknown>
}

export type FhState = {
  status: 'idle' | 'connecting' | 'open' | 'closed'
  events: FhEvent[]
  /** Arrived while paused, shown on resume. */
  held: number
  error?: string
  version: number
}

const MAX = 600
const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
function base32(bytes: Uint8Array): string {
  let out = ''
  let bits = 0
  let v = 0
  for (const b of bytes) {
    v = (v << 8) | b
    bits += 8
    while (bits >= 5) {
      out += B32[(v >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31]
  return out
}
// DAG-CBOR links: tag 42 over the CID bytes behind a 0x00 multibase prefix
const tags: Record<number, TagDecoder> = { 42: (inner) => `b${base32((inner() as Uint8Array).subarray(1))}` }

let st: FhState = { status: 'idle', events: [], held: 0, version: 0 }
let heldQ: FhEvent[] = []
let seqId = 0
let ws: WebSocket | undefined
let retry = 1000
let retryTimer: ReturnType<typeof setTimeout> | undefined
const subs = new Set<() => void>()
const emit = (p: Partial<FhState>) => {
  st = { ...st, ...p, version: st.version + 1 }
  subs.forEach((l) => l())
}

function parseFrame(buf: ArrayBuffer): FhEvent | undefined {
  const bytes = new Uint8Array(buf)
  const [header, rest] = decodeFirst(bytes, { tags }) as [{ op: number; t?: string }, Uint8Array]
  if (header.op !== 1 || !header.t) return undefined
  const body = decode(rest, { tags, allowUndefined: true }) as Record<string, any>
  const kind = header.t.replace(/^#/, '') as FhKind
  if (!['commit', 'identity', 'account', 'sync'].includes(kind)) return undefined
  const did: string = body.repo ?? body.did ?? ''
  const blocks = body.blocks instanceof Uint8Array ? body.blocks.length : undefined
  const shown: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(body)) shown[k] = v instanceof Uint8Array ? `<${v.length} bytes>` : typeof v === 'bigint' ? v.toString() : v
  if (kind === 'identity' && body.handle) handles.set(did, body.handle)
  return {
    id: ++seqId,
    seq: String(body.seq),
    kind,
    did,
    at: Date.now(),
    time: body.time,
    ops: Array.isArray(body.ops) ? body.ops.map((o: any) => ({ action: o.action, path: o.path, cid: o.cid ?? undefined })) : [],
    handle: body.handle,
    active: body.active,
    status: body.status,
    rev: body.rev,
    commit: typeof body.commit === 'string' ? body.commit : undefined,
    blocksBytes: blocks,
    frameBytes: bytes.length,
    body: shown,
  }
}

let pending: FhEvent[] = []
let flushTimer: ReturnType<typeof setTimeout> | undefined
function flush() {
  flushTimer = undefined
  if (!pending.length) return
  const evs = pending
  pending = []
  for (const e of evs) if (!handles.has(e.did)) wantHandle(e.did)
  if (getLive().paused) {
    heldQ.push(...evs)
    if (heldQ.length > MAX) heldQ = heldQ.slice(-MAX)
    emit({ held: heldQ.length })
    return
  }
  emit({ events: [...st.events, ...evs].slice(-MAX) })
}

function connect() {
  clearTimeout(retryTimer)
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const sock = new WebSocket(`${proto}//${location.host}/xrpc/com.atproto.sync.subscribeRepos`)
  sock.binaryType = 'arraybuffer'
  ws = sock
  emit({ status: 'connecting', error: undefined })
  sock.onopen = () => {
    retry = 1000
    emit({ status: 'open' })
  }
  sock.onmessage = (m) => {
    try {
      const e = parseFrame(m.data as ArrayBuffer)
      if (!e) return
      pending.push(e)
      // batch renders: a busy PDS sends hundreds of frames a second
      flushTimer ??= setTimeout(flush, 250)
    } catch (err) {
      emit({ error: `Undecodable frame: ${err instanceof Error ? err.message : err}` })
    }
  }
  sock.onclose = (ev) => {
    if (ws !== sock) return
    ws = undefined
    emit({ status: 'closed', error: ev.reason || (ev.code !== 1000 ? `closed (${ev.code})` : undefined) })
    if (subs.size) {
      retryTimer = setTimeout(connect, retry)
      retry = Math.min(retry * 2, 15_000)
    }
  }
}

/** Shows what arrived while paused. Called by the shell when live updates resume. */
export function releaseHeld() {
  if (!heldQ.length) return
  const evs = heldQ
  heldQ = []
  emit({ events: [...st.events, ...evs].slice(-MAX), held: 0 })
}

function subscribe(l: () => void) {
  subs.add(l)
  if (subs.size === 1 && !ws) connect()
  return () => {
    subs.delete(l)
    if (!subs.size) {
      clearTimeout(retryTimer)
      const s = ws
      ws = undefined
      s?.close(1000)
      st = { ...st, status: 'idle' }
    }
  }
}

export const useFirehose = () => useSyncExternalStore(subscribe, () => st)
export const findEvent = (seq: string) => st.events.find((e) => e.seq === seq)

/** Events per second over the last 10 s of arrivals. */
export function eventRate(events: FhEvent[], now = Date.now()): number {
  let n = 0
  for (let i = events.length - 1; i >= 0 && events[i].at > now - 10_000; i--) n++
  return n / 10
}

// ---------------------------------------------------------------- handles

const handles = new Map<string, string>()
const asked = new Set<string>()
let want: string[] = []
let handleTimer: ReturnType<typeof setTimeout> | undefined
const handleSubs = new Set<() => void>()
let handleVersion = 0

function wantHandle(did: string) {
  if (!did || asked.has(did)) return
  asked.add(did)
  want.push(did)
  handleTimer ??= setTimeout(resolveHandles, 400)
}

async function resolveHandles() {
  handleTimer = undefined
  const batch = want.splice(0, 50)
  if (want.length) handleTimer = setTimeout(resolveHandles, 400)
  if (!batch.length) return
  try {
    const r: { infos: { did: string; handle: string }[] } = await admin('com.atproto.admin.getAccountInfos', { params: { dids: batch } })
    for (const i of r.infos) handles.set(i.did, i.handle)
    handleVersion++
    handleSubs.forEach((l) => l())
  } catch {
    /* DIDs keep showing until the next identity event */
  }
}

/** The handle for a DID on this PDS, looked up in batches (undefined until known). */
export function useHandle(did: string | undefined): string | undefined {
  useSyncExternalStore(
    (l) => {
      handleSubs.add(l)
      return () => {
        handleSubs.delete(l)
      }
    },
    () => handleVersion,
  )
  if (did && !handles.has(did)) wantHandle(did)
  return did ? handles.get(did) : undefined
}
export const handleOf = (did: string) => handles.get(did)
export const handlesVersion = () => handleVersion
export function subscribeHandles(l: () => void) {
  handleSubs.add(l)
  return () => {
    handleSubs.delete(l)
  }
}
