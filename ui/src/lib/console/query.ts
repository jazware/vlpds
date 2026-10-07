import { focusManager, keepPreviousData, QueryCache, QueryClient, QueryObserver, useQuery, type QueryKey } from '@tanstack/react-query'
import { getAdminUnlock, subscribeAdmin, XrpcError } from '../xrpc'
import { getLive, heartbeatFailed, heartbeatOk, subscribeLive } from './live'

// The console's one client cache (CONSOLE.md "Data layer"). Every read is a query with a
// structured key (keys.ts); the change feed (push.ts) and every action (mutate.ts) invalidate
// exactly the keys that changed. Polling is a fallback: slow while the feed is up, faster while
// it's down, never in a hidden tab, and stopped while the console is paused.

/** What a panel gets from a query: data kept while it refetches, the last error, when it answered. */
export type Load<T> = { data?: T; error?: unknown; loading: boolean; at?: number; reload: () => void }

const isAuth = (e: unknown) => e instanceof XrpcError && (e.status === 401 || e.status === 403)

export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    // getClusterStatus is the heartbeat: when it fails the shell says "Not updating"
    onSuccess: (_d, q) => {
      if (q.queryKey[0] === 'cluster') heartbeatOk()
    },
    onError: (e, q) => {
      if (q.queryKey[0] === 'cluster' && !isAuth(e)) heartbeatFailed(e)
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      gcTime: 5 * 60_000,
      retry: (n, e) => n < 2 && !(e instanceof XrpcError && e.status < 500),
      retryDelay: (n) => Math.min(4000, 500 * 2 ** n),
      refetchOnWindowFocus: true,
      refetchIntervalInBackground: false,
    },
  },
})

// Locking the console forgets everything it read.
let unlocked = getAdminUnlock()
subscribeAdmin(() => {
  const now = getAdminUnlock()
  if (!now && unlocked) queryClient.clear()
  unlocked = now
})

// Pausing (space) is the console looking away: interval ticks and focus refetches stop, a
// change only marks its queries stale, and resuming refetches what went stale meanwhile. A
// detail opened while paused still loads.
let wasPaused = getLive().paused
subscribeLive(() => {
  const p = getLive().paused
  if (p === wasPaused) return
  wasPaused = p
  focusManager.setFocused(p ? false : undefined)
  // a focus event only refetches in a visible tab: catch up explicitly
  if (!p) void queryClient.refetchQueries({ type: 'active', stale: true })
})

/**
 * How often a query polls. `stream`: telemetry read as a series (cluster status, metrics,
 * segments), every `ms` whatever else happens. Otherwise `ms` is the fallback while the change
 * feed is down, and four times it (at most two minutes) while the feed is up.
 */
export function every(ms: number, stream = false) {
  return () => (stream || getLive().push !== 'live' ? ms : Math.min(ms * 4, 120_000))
}

/**
 * A response is dropped when the cache already holds something newer: by the entity's own
 * `version` where it has one, else by when it was read (an action's answer or a list row
 * written after this request started wins).
 */
export function guarded<T>(key: QueryKey, fn: (signal: AbortSignal) => Promise<T>, version?: (d: T) => number | string | undefined) {
  return async ({ signal }: { signal: AbortSignal }): Promise<T> => {
    const started = Date.now()
    const next = await fn(signal)
    const st = queryClient.getQueryState<T>(key)
    if (st?.data === undefined) return next
    if (version) {
      const a = version(st.data)
      const b = version(next)
      if (a !== undefined && b !== undefined && a > b) return st.data
      return next
    }
    return st.dataUpdatedAt > started ? st.data : next
  }
}

/** Writes an entity read somewhere else (a list row, an action's answer) unless the cache holds a newer one. */
export function hydrate<T>(key: QueryKey, data: T, readAt: number, version?: (d: T) => number | string | undefined) {
  const st = queryClient.getQueryState<T>(key)
  if (st?.data !== undefined) {
    if (version) {
      const a = version(st.data)
      const b = version(data)
      if (a !== undefined && b !== undefined && a > b) return
    } else if (st.dataUpdatedAt > readAt) return
  }
  queryClient.setQueryData(key, data, { updatedAt: readAt })
}

export type QueryDef<T> = {
  key: QueryKey
  fn: (signal: AbortSignal) => Promise<T>
  /** Fallback poll, ms (see `every`); none: only on changes, focus and mount. */
  poll?: number
  stream?: boolean
  version?: (d: T) => number | string | undefined
  staleTime?: number
  enabled?: boolean
  /** Keep showing the previous key's data while a new key loads (a search, a filter). */
  keep?: boolean
}

export function options<T>(d: QueryDef<T>) {
  return {
    queryKey: d.key,
    queryFn: guarded(d.key, d.fn, d.version),
    refetchInterval: d.poll ? every(d.poll, d.stream) : (false as const),
    staleTime: d.stream ? 0 : d.staleTime,
    enabled: d.enabled,
    placeholderData: d.keep ? keepPreviousData : undefined,
  }
}

function toLoad<T>(q: { data?: T; error: unknown; isPending: boolean; isFetching: boolean; dataUpdatedAt: number }, reload: () => void): Load<T> {
  return {
    data: q.data,
    error: q.error ?? undefined,
    loading: q.isPending || (q.isFetching && q.data === undefined),
    at: q.dataUpdatedAt || undefined,
    reload,
  }
}

/** A query in a component: the data, kept across refetches, with its error and age. */
export function useAdminQuery<T>(d: QueryDef<T>): Load<T> {
  const q = useQuery(options(d))
  return toLoad({ ...q, isPending: q.isPending && d.enabled !== false }, () => void q.refetch())
}

/** A query several parts of the console read: one copy, fetched while any of them is on screen. */
export function shared<T>(d: QueryDef<T>) {
  return {
    key: d.key,
    options: () => options(d),
    use: (): Load<T> => useAdminQuery(d),
    /** The cached state, for code outside React (the palette, the shell's attention list). */
    get: (): Load<T> => {
      const st = queryClient.getQueryState<T>(d.key)
      return {
        data: st?.data,
        error: st?.error ?? undefined,
        loading: !st || st.status === 'pending',
        at: st?.dataUpdatedAt || undefined,
        reload: () => void queryClient.invalidateQueries({ queryKey: d.key }),
      }
    },
    refresh: () => queryClient.invalidateQueries({ queryKey: d.key }),
    /** Fetches it unless it's cached and fresh, whether or not anything shows it (the palette). */
    prefetch: () => queryClient.prefetchQuery(options(d)),
    /** The current answer from the server, for an edit that must start from it. */
    fresh: () => queryClient.fetchQuery({ ...options(d), staleTime: 0 }),
  }
}

/** Keeps a query fetched (and polled) while `l` is subscribed: for stores outside React. */
export function observe<T>(d: QueryDef<T>, l: () => void): () => void {
  const o = new QueryObserver(queryClient, options(d))
  return o.subscribe(() => l())
}
