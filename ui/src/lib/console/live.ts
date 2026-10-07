import { useSyncExternalStore } from 'react'
import { XrpcError } from '../xrpc'

// The console's live state: paused (space), stale (the heartbeat query is failing: "console
// offline"), the change feed's connection, and the debug toggle that shows where each panel's
// data comes from. One store, read with useLiveState().

/** The change feed (push.ts): `live` while connected, `down` while it reconnects, `off` on a server without it. */
export type PushState = 'connecting' | 'live' | 'down' | 'off'

export type LiveState = {
  paused: boolean
  /** The heartbeat query (getClusterStatus) failed and hasn't recovered since. */
  stale: boolean
  /** Last time the heartbeat answered. */
  lastOkAt: number
  staleError?: string
  showSources: boolean
  push: PushState
  /** Last change the feed delivered. */
  pushAt?: number
}

const SRC_KEY = 'vlpds.console.sources'
let state: LiveState = {
  paused: false,
  push: 'connecting',
  stale: false,
  lastOkAt: 0,
  showSources: (() => {
    try {
      return localStorage.getItem(SRC_KEY) === '1'
    } catch {
      return false
    }
  })(),
}
const listeners = new Set<() => void>()
function set(p: Partial<LiveState>) {
  state = { ...state, ...p }
  listeners.forEach((l) => l())
}
export const subscribeLive = (l: () => void) => {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}
export const getLive = () => state
export const useLiveState = () => useSyncExternalStore(subscribeLive, getLive)

export function setPush(push: PushState, pushAt?: number) {
  if (push !== state.push || (pushAt && pushAt - (state.pushAt ?? 0) > 1000)) set({ push, pushAt: pushAt ?? state.pushAt })
}

export function setPaused(p: boolean) {
  if (p !== state.paused) set({ paused: p })
}
export const togglePaused = () => set({ paused: !state.paused })
export function toggleSources() {
  const v = !state.showSources
  try {
    localStorage.setItem(SRC_KEY, v ? '1' : '0')
  } catch {
    /* per-tab */
  }
  set({ showSources: v })
}
export function heartbeatOk() {
  if (state.stale || !state.lastOkAt || Date.now() - state.lastOkAt > 1000) set({ stale: false, staleError: undefined, lastOkAt: Date.now() })
}
export function heartbeatFailed(e: unknown) {
  set({ stale: true, staleError: e instanceof Error ? e.message : String(e) })
}

/** Unknown XRPC methods (an older vlpds): the proxy fallback answers 501 or 404. */
export function isUnsupported(e: unknown): boolean {
  return e instanceof XrpcError && (e.status === 501 || e.status === 404 || e.error === 'MethodNotImplemented' || e.error === 'MethodNotSupported')
}
