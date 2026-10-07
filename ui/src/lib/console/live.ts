import { useSyncExternalStore } from 'react'
import { XrpcError } from '../xrpc'

// The console's live state: paused (space), stale (the heartbeat poll is failing: "console
// offline"), and the debug toggle that shows where each panel's data comes from. One store,
// read with useLiveState().

export type LiveState = {
  paused: boolean
  /** The heartbeat poll (getClusterStatus) failed and hasn't recovered since. */
  stale: boolean
  /** Last time the heartbeat answered. */
  lastOkAt: number
  staleError?: string
  showSources: boolean
}

const SRC_KEY = 'vlpds.console.sources'
let state: LiveState = {
  paused: false,
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
const subscribe = (l: () => void) => {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}
export const getLive = () => state
export const useLiveState = () => useSyncExternalStore(subscribe, getLive)

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

// ---------------------------------------------------------------- pollers

export type PollState<T> = { data?: T; error?: unknown; at?: number; loading: boolean }

/**
 * A shared poll: every component that calls `use()` sees the same data, and the fetch runs only
 * while at least one is mounted. Paused (space) skips ticks, so every panel freezes together.
 * `heartbeat` marks the console stale when this poll fails.
 */
export function createPoller<T>(fetcher: () => Promise<T>, ms: number, opts: { heartbeat?: boolean } = {}) {
  let ps: PollState<T> = { loading: true }
  const subs = new Set<() => void>()
  let timer: ReturnType<typeof setInterval> | undefined
  let inflight = false
  const emit = (p: Partial<PollState<T>>) => {
    ps = { ...ps, ...p }
    subs.forEach((l) => l())
  }
  async function tick(force = false) {
    if (inflight || (!force && state.paused)) return
    inflight = true
    try {
      const data = await fetcher()
      emit({ data, error: undefined, at: Date.now(), loading: false })
      if (opts.heartbeat) heartbeatOk()
    } catch (e) {
      emit({ error: e, loading: false })
      // a 401 already sent the console back to the token form
      if (opts.heartbeat && !(e instanceof XrpcError && e.status === 401)) heartbeatFailed(e)
    } finally {
      inflight = false
    }
  }
  const subscribeP = (l: () => void) => {
    subs.add(l)
    if (subs.size === 1) {
      tick(true)
      timer = setInterval(tick, ms)
    }
    return () => {
      subs.delete(l)
      if (!subs.size && timer) {
        clearInterval(timer)
        timer = undefined
      }
    }
  }
  return {
    use: (): PollState<T> => useSyncExternalStore(subscribeP, () => ps),
    get: () => ps,
    refresh: () => tick(true),
  }
}

/** Unknown XRPC methods (an older vlpds): the proxy fallback answers 501 or 404. */
export function isUnsupported(e: unknown): boolean {
  return e instanceof XrpcError && (e.status === 501 || e.status === 404 || e.error === 'MethodNotImplemented' || e.error === 'MethodNotSupported')
}
