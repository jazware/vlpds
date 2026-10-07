import { MutationObserver, type InfiniteData, type QueryKey } from '@tanstack/react-query'
import type { AccountRow, ListAccountsResult } from '../adminApi'
import { apply, type Change } from './changes'
import { K } from './keys'
import { queryClient } from './query'

// Every console action goes through `mutate`: it runs the call, writes what the answer tells us
// straight into the cache (`write`), and invalidates what changed (`changes`, the change feed's
// vocabulary) so this tab doesn't wait for the feed. `optimistic` patches the cache before the
// call and gets its rollback back on failure: only for edits whose result is obvious.

export type Mutation<R> = {
  run: () => Promise<R>
  /** What the action changed, for invalidation (an audit entry is implied). */
  changes: Change[] | ((r: R) => Change[])
  /** Writes the answer into the cache. */
  write?: (r: R) => void | Promise<void>
  /** Patches the cache before the call; returns how to undo it. */
  optimistic?: () => () => void
}

export async function mutate<R>(m: Mutation<R>): Promise<R> {
  const obs = new MutationObserver<R, unknown, void, (() => void) | undefined>(queryClient, {
    mutationFn: () => m.run(),
    onMutate: () => m.optimistic?.(),
    onError: (_e, _v, undo) => undo?.(),
    onSuccess: async (r) => {
      await m.write?.(r)
      const cs = typeof m.changes === 'function' ? m.changes(r) : m.changes
      apply([...cs, { kind: 'audit' }], { now: true })
    },
  })
  try {
    return await obs.mutate()
  } finally {
    obs.reset()
  }
}

/** Sets an entity from an action's answer, cancelling any read of it already in flight (it started before the action landed). */
export async function put<T>(key: QueryKey, data: T) {
  await queryClient.cancelQueries({ queryKey: key, exact: true })
  queryClient.setQueryData(key, data)
}

/** Updates every cached copy of one account's row: the per-account query and its rows in every loaded list. */
export function patchAccountRow(did: string, f: (r: AccountRow) => AccountRow | null): () => void {
  const snapshots: [QueryKey, unknown][] = []
  const row = queryClient.getQueryData<AccountRow>(K.accountRow(did))
  if (row) {
    snapshots.push([K.accountRow(did), row])
    const next = f(row)
    if (next) queryClient.setQueryData(K.accountRow(did), next)
  }
  for (const [key, data] of queryClient.getQueriesData<InfiniteData<ListAccountsResult>>({ queryKey: K.accounts() })) {
    if (!data?.pages) continue
    if (!data.pages.some((p) => p.accounts.some((a) => a.did === did))) continue
    snapshots.push([key, data])
    queryClient.setQueryData<InfiniteData<ListAccountsResult>>(key, {
      ...data,
      pages: data.pages.map((p) => ({
        ...p,
        accounts: p.accounts.flatMap((a) => {
          if (a.did !== did) return [a]
          const n = f(a)
          return n ? [n] : []
        }),
      })),
    })
  }
  return () => snapshots.forEach(([k, d]) => queryClient.setQueryData(k, d))
}
