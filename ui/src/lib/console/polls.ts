import { admin } from '../xrpc'
import { lockouts } from './adminAdapter'
import { createPoller } from './live'

// Shared polls the shell (badges, banners) and several pages read. Each runs only while
// something on screen uses it.

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
export const subscribersPoll = createPoller(() => admin<SubscriberList>('vlpds.admin.listFirehoseSubscribers'), 5000)

/** The live tail of a console open in this browser (same user agent): probably this tab. */
export const isThisBrowser = (s: Subscriber) => s.userAgent === navigator.userAgent

/** A live subscriber more than 30 s behind the stream (a backfill is behind by design). */
export const isSlow = (s: Subscriber) => s.state === 'live' && !s.shard && (s.lagMs ?? 0) > 30_000

export type SubjectRef = { kind: 'account' | 'record' | 'blob' | 'space' | 'spaceRepo'; did: string; uri?: string; cid?: string }
export type Case = {
  id: string
  createdAt: string
  updatedAt: string
  status: 'open' | 'actioned' | 'dismissed' | 'restored'
  source: string
  subjects: SubjectRef[]
  notes: { at: string; actor: string; text: string }[]
}
export const openCasesPoll = createPoller(async () => (await admin<{ cases: Case[] }>('vlpds.admin.listCases', { params: { status: 'open' } })).cases, 15000)

export type AuditEntry = { id: string; at: string; actor: string; ip?: string; node: string; action: string; subject?: SubjectRef; reason?: string; caseId?: string }
export const auditPoll = createPoller(async () => (await admin<{ entries: AuditEntry[] }>('vlpds.admin.getAuditLog', { params: { limit: 8 } })).entries, 30000)

export const lockoutsPoll = createPoller(lockouts, 15000)
