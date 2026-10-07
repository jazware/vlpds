import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { getAdminOperator, getAdminUnlock, getSession, subscribeAdmin, subscribeSession } from './xrpc'

export const useSession = () => useSyncExternalStore(subscribeSession, getSession)
/** The token or a proxy's sign-in; null while the console is locked. */
export const useAdminUnlock = () => useSyncExternalStore(subscribeAdmin, getAdminUnlock)
/** The operator a proxy signed in, if that's how the console is unlocked. */
export const useAdminOperator = () => useSyncExternalStore(subscribeAdmin, getAdminOperator)

export type Load<T> = { data?: T; error?: unknown; loading: boolean; reload: () => void }

/** Runs `fn` when `deps` change (and every `pollMs`, if set). Keeps the last data while reloading. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[], pollMs?: number): Load<T> {
  const [state, setState] = useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true })
  const [tick, setTick] = useState(0)
  const fnRef = useRef(fn)
  fnRef.current = fn
  useEffect(() => {
    let live = true
    setState((s) => ({ ...s, loading: true }))
    fnRef
      .current()
      .then((data) => live && setState({ data, loading: false }))
      .catch((error) => live && setState((s) => ({ data: s.data, error, loading: false })))
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  useEffect(() => {
    if (!pollMs) return
    // keeps polling in background tabs too: an operator glancing back at the
    // console should see current data, not a gap
    const id = setInterval(() => setTick((t) => t + 1), pollMs)
    return () => clearInterval(id)
  }, [pollMs])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { ...state, reload }
}

/** Wraps an async action with busy/error/done state for a form. */
export function useAction<A extends unknown[], R>(fn: (...a: A) => Promise<R>) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const run = useCallback(
    async (...a: A): Promise<R | undefined> => {
      setBusy(true)
      setError(undefined)
      try {
        return await fn(...a)
      } catch (e) {
        setError(e)
        return undefined
      } finally {
        setBusy(false)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [fn],
  )
  return { run, busy, error, setError }
}

// ---------------------------------------------------------------- theme

export type Theme = 'light' | 'dark' | 'system'
const TKEY = 'vlpds.theme'
const themeListeners = new Set<() => void>()
let theme: Theme = (() => {
  try {
    return (localStorage.getItem(TKEY) as Theme) || 'system'
  } catch {
    return 'system'
  }
})()

function applyTheme() {
  const root = document.documentElement
  if (theme === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', theme)
}
applyTheme()

const media = window.matchMedia('(prefers-color-scheme: dark)')
media.addEventListener('change', () => themeListeners.forEach((l) => l()))

export function setTheme(t: Theme) {
  theme = t
  try {
    localStorage.setItem(TKEY, t)
  } catch {
    /* per-tab only */
  }
  applyTheme()
  themeListeners.forEach((l) => l())
}

function subscribeTheme(l: () => void) {
  themeListeners.add(l)
  return () => {
    themeListeners.delete(l)
  }
}

export const useTheme = () => useSyncExternalStore(subscribeTheme, () => theme)
/** The theme actually showing ("system" resolved). */
export const useResolvedTheme = () =>
  useSyncExternalStore(subscribeTheme, () => (theme === 'system' ? (media.matches ? 'dark' : 'light') : theme))
