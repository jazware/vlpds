import type { QueryKey } from '@tanstack/react-query'
import { K } from './keys'
import { getLive } from './live'
import { queryClient } from './query'

// What a change touches. The change feed (push.ts) and every action (mutate.ts) speak the same
// vocabulary as the server's (src/xrpc/changes.rs KINDS): `{kind, id}`. `apply` invalidates the
// entity's own queries at once and the lists and aggregates that contain it at most once a
// second, so a burst (an import, a loadgen run) refetches a list once, not per change.

export type Change = { kind: string; id?: string; version?: number; node?: string }

type Rule = { entity?: (id: string) => QueryKey[]; lists?: QueryKey[] }

const RULES: Record<string, Rule> = {
  audit: { lists: [K.audit()], entity: (id) => [K.auditEntry(id)] },
  account: { entity: (did) => [K.account(did)], lists: [K.accounts(), K.domains, K.overQuota] },
  case: { entity: (id) => [K.case(id)], lists: [K.cases()] },
  takedown: { lists: [K.takedowns] },
  lockout: { entity: (did) => [K.account(did)], lists: [K.lockouts] },
  mail: { lists: [K.mail()] },
  subscriber: { lists: [K.subscribers] },
  cluster: { entity: () => [K.cluster] },
  shard: { entity: () => [K.cluster] },
  node: { entity: () => [K.cluster] },
  domain: { lists: [K.domains] },
  invite: { lists: [K.invites] },
  config: {
    entity: (id) => (id === 'ratelimits' ? [K.ratelimits] : id === 'crawlers' ? [K.crawlers] : [K.cluster, K.config]),
  },
  ratelimits: { entity: () => [K.ratelimits] },
  space: { entity: (uri) => [K.space(uri)], lists: [K.spaces] },
}

const THROTTLE_MS = 1000
const lastAt = new Map<string, number>()
const trailing = new Map<string, ReturnType<typeof setTimeout>>()

function refetchType(): 'active' | 'none' {
  return getLive().paused ? 'none' : 'active'
}

function invalidate(key: QueryKey) {
  void queryClient.invalidateQueries({ queryKey: key, refetchType: refetchType() })
}

/** Leading edge at once, then at most once per second with a trailing call. */
function throttled(key: QueryKey) {
  const h = JSON.stringify(key)
  const now = Date.now()
  const last = lastAt.get(h) ?? 0
  if (now - last >= THROTTLE_MS) {
    lastAt.set(h, now)
    invalidate(key)
    return
  }
  if (trailing.has(h)) return
  trailing.set(
    h,
    setTimeout(() => {
      trailing.delete(h)
      lastAt.set(h, Date.now())
      invalidate(key)
    }, THROTTLE_MS - (now - last)),
  )
}

/** Invalidates what each change touches. `now`: an action of this tab, so its lists refetch at once too. */
export function apply(changes: Change[], o: { now?: boolean } = {}) {
  const lists = new Map<string, QueryKey>()
  for (const c of changes) {
    if (c.kind === 'resync') return resync()
    const r = RULES[c.kind]
    if (!r) continue
    for (const k of r.entity?.(c.id ?? '') ?? []) invalidate(k)
    for (const k of r.lists ?? []) lists.set(JSON.stringify(k), k)
  }
  for (const k of lists.values()) {
    if (!o.now) throttled(k)
    else {
      // the feed's echo of this action within the second becomes the trailing refetch
      lastAt.set(JSON.stringify(k), Date.now())
      invalidate(k)
    }
  }
}

/** Missed changes: everything is stale, and what's on screen refetches. */
export function resync() {
  void queryClient.invalidateQueries({ refetchType: refetchType() })
}
