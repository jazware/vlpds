import { admin } from '../xrpc'
import { lockouts } from './adminAdapter'
import { K } from './keys'
import type { AuditEntry, Case } from './moderation'
import { hydrate, shared } from './query'

// Queries the shell (badges, banners) and several pages read. Each is fetched while something on
// screen uses it, refetched when the change feed names it, and polled only as a fallback.

export type Subscriber = {
  node: string
  conn: string
  labelled: boolean
  ip: string | null
  ptr: string | null
  ptrVerified: boolean
  asn: number | null
  asName: string | null
  asCountry: string | null
  userAgent: string
  relay: string | null
  connectedAt: number
  cursor: string | null
  shard: string | null
  state: 'live' | 'backfilling'
  lastSeq: string
  events: number
  bytes: number
  lagBytes: number | null
  lagMs: number | null
  lagEvents: number | null
  disconnectedAt?: number
  reason?: string
}
export type SubscriberList = {
  node: string
  total: number
  live: number
  backfilling: number
  subscribers: Subscriber[]
  recentDisconnects: Subscriber[]
  nodes: { node: string; self: boolean; reachable: boolean; subscribers?: number; backfilling?: number; eventsEmitted?: number; bytesSent?: number }[]
  unreachableNodes?: string[]
  time: number
}
export const subscribersQ = shared({
  key: K.subscribers,
  fn: (signal) => admin<SubscriberList>('vlpds.admin.listFirehoseSubscribers', { signal }),
  poll: 10_000,
  version: (d) => d.time,
})

/** The live tail of a console open in this browser (same user agent): probably this tab. */
export const isThisBrowser = (s: Subscriber) => s.userAgent === navigator.userAgent

/** A live subscriber more than 30 s behind the stream (a backfill is behind by design). */
export const isSlow = (s: Subscriber) => s.state === 'live' && !s.shard && (s.lagMs ?? 0) > 30_000

export const openCasesQ = shared({
  key: K.cases({ status: 'open' }),
  fn: async (signal) => {
    const at = Date.now()
    const cases = (await admin<{ cases: Case[] }>('vlpds.admin.listCases', { params: { status: 'open' }, signal })).cases
    for (const c of cases) hydrate(K.case(c.id), c, at, (x: Case) => x.updatedAt)
    return cases
  },
  poll: 30_000,
})

export const recentAuditQ = shared({
  key: K.audit({ limit: 8 }),
  fn: async (signal) => {
    const at = Date.now()
    const entries = (await admin<{ entries: AuditEntry[] }>('vlpds.admin.getAuditLog', { params: { limit: 8 }, signal })).entries
    for (const e of entries) hydrate(K.auditEntry(e.id), e, at)
    return entries
  },
  poll: 60_000,
})

export const lockoutsQ = shared({ key: K.lockouts, fn: () => lockouts(), poll: 30_000 })
