import { useSyncExternalStore } from 'react'
import { admin } from '../xrpc'
import { auditPoll, openCasesPoll } from './polls'

// Moderation data: the vlpds.admin.* moderation endpoints (src/xrpc/moderation.rs), their
// shapes, and a change counter every moderation view reloads on.

export type Kind = 'account' | 'record' | 'blob' | 'space'
/** `spaceRepo`: an audited operator read of an account's repo in a space (audit entries only). */
export type SubjectRef = { kind: Kind | 'spaceRepo'; did: string; uri?: string; cid?: string }
export type Resolved = { kind: Kind; did: string; handle: string; uri?: string; cid?: string }
export type BlobView = {
  cid: string
  takendown: boolean
  stored: boolean
  quarantined: boolean
  mimeType?: string
  size?: number
  purgeAfterMs?: number
  takedown?: { ref?: string; quarantinedAt?: number; purgedAtMs?: number }
}
export type Quota = {
  bytes: number
  uploadsToday: number
  limitBytes: number
  limitUploadsPerDay: number
  override: { bytes?: number; uploadsPerDay?: number }
  defaults: { bytes: number; uploadsPerDay: number }
  over: boolean
}
export type SubjectDetail = {
  account: { did: string; handle: string; email?: string; createdAt: string; status?: string; takedown: { applied: boolean; ref?: string } }
  quota: Quota
  record?: { uri: string; exists: boolean; takendown: boolean; cid?: string; value?: unknown; blobs?: BlobView[] }
  blob?: BlobView
  /** What a space record is, never what it says (reading it is audited). */
  spaceRecord?: { uri: string; space: string; exists: boolean; takendown: boolean; cid?: string }
  space?: { uri: string; exists: boolean; deleted: boolean; takendown: boolean }
}
export type CaseStatus = 'open' | 'actioned' | 'dismissed' | 'restored'
export type CaseAction = { at: string; auditId: string; action: string; subject: SubjectRef; reason?: string; actor: string }
export type Case = {
  id: string
  createdAt: string
  updatedAt: string
  status: CaseStatus
  source: string
  subjects: SubjectRef[]
  notes: { at: string; actor: string; auth?: string; ip?: string; text: string }[]
  actions: CaseAction[]
}
export type AuditEntry = { id: string; at: string; actor: string; auth?: string; ip?: string; node: string; action: string; subject?: SubjectRef; reason?: string; caseId?: string; detail?: any }
export type TakedownEntry = {
  subject: SubjectRef
  reason?: string
  ref?: string
  caseId?: string
  at: string
  actor: string
  auditId?: string
  quarantined?: boolean
  purgeAfterMs?: number
  purgedAtMs?: number
  size?: number
}

export const CASE_STATUSES: CaseStatus[] = ['open', 'actioned', 'dismissed', 'restored']
export const CASE_TONE: Record<CaseStatus, 'warn' | 'err' | 'idle' | 'ok'> = { open: 'warn', actioned: 'err', dismissed: 'idle', restored: 'ok' }

/** What a takedown of each kind does, for the confirm dialog. */
export const SEMANTICS: Record<Kind, string[]> = {
  account: [
    'Its repo stops being served and a #account event tells relays and AppViews.',
    'Every session is revoked.',
    'Restoring reverses all of it except the revoked sessions.',
  ],
  record: [
    'Hidden from this PDS’s record reads (getRecord, listRecords).',
    'It stays in the signed repo, visible to relays and AppViews until the user deletes it. Ask Bluesky Trust & Safety to act on their copy.',
  ],
  blob: [
    'Stops being served at once and can’t be uploaded or referenced again.',
    'Its bytes move to quarantine and are deleted after the quarantine period unless restored.',
    'Copies already in AppView or CDN caches aren’t purged by this.',
  ],
  space: [
    'Nobody gets a credential to read the space; syncers can’t list its writers or register for its notifications.',
    'Members’ notifies are dropped. The records stay on their authors’ PDSes.',
  ],
}

/** The string resolveSubject takes back for a subject (the slide-over id). */
export const subjectQuery = (s: SubjectRef) =>
  s.kind === 'record' || s.kind === 'space' || s.kind === 'spaceRepo' ? s.uri! : s.kind === 'blob' ? `${s.did} ${s.cid}` : s.did

/** at://did/collection/rkey → collection/rkey. */
export const shortUri = (uri: string) => uri.replace(/^at:\/\/[^/]+\//, '')

/** at://{authority}/space/{type}/{skey}/{author}/{collection}/{rkey} */
export function spaceRecordParts(uri: string) {
  const p = uri.replace(/^at:\/\//, '').split('/')
  return { space: `at://${p.slice(0, 4).join('/')}`, collection: p[5], rkey: p[6] }
}

/** Decimal units, as --blob-quota-gb. */
export const fmtGB = (n: number) => (n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e3).toFixed(1)} kB`)

// ---------------------------------------------------------------- change counter

let version = 0
const subs = new Set<() => void>()
/** Call after any moderation write: views reload, and the shell's badges refresh. */
export function modChanged() {
  version++
  subs.forEach((l) => l())
  openCasesPoll.refresh()
  auditPoll.refresh()
}
export const useModVersion = () =>
  useSyncExternalStore(
    (l) => {
      subs.add(l)
      return () => {
        subs.delete(l)
      }
    },
    () => version,
  )

// ---------------------------------------------------------------- calls

/** Audit entries seen by any view, so an entry's slide-over opens without a reload. */
export const auditSeen = new Map<string, AuditEntry>()

export async function getAuditLog(p: { limit?: number; did?: string; space?: string } = {}) {
  const r = await admin<{ entries: AuditEntry[] }>('vlpds.admin.getAuditLog', { params: p })
  for (const e of r.entries) auditSeen.set(e.id, e)
  return r.entries
}

export const listCases = (status?: string) => admin<{ cases: Case[] }>('vlpds.admin.listCases', { params: { status } }).then((r) => r.cases)

/** Cases with a subject of this account, or (with `subject`, a record URI or blob CID) of that one record or blob. */
export const listCasesAbout = (did: string, subject?: string) =>
  admin<{ cases: Case[] }>('vlpds.admin.listCases', { params: { did, subject } }).then((r) => r.cases)

export const getCase = (id: string) => admin<Case>('vlpds.admin.getCase', { params: { id } })
export const listTakedowns = (kind?: string) => admin<{ takedowns: TakedownEntry[] }>('vlpds.admin.listTakedowns', { params: { kind } }).then((r) => r.takedowns)
export const listOverQuota = () => admin<{ accounts: { did: string; bytes: number; limit: number; at: string }[] }>('vlpds.admin.listOverQuota').then((r) => r.accounts)
export const resolveSubject = (q: string) => admin<Resolved>('vlpds.admin.resolveSubject', { params: { q } })
export const getSubject = (s: { did: string; uri?: string; cid?: string }) => admin<SubjectDetail>('vlpds.admin.getSubject', { params: { did: s.did, uri: s.uri, cid: s.cid } })

export async function updateCase(id: string, body: { status?: CaseStatus; note?: string; source?: string; addSubject?: SubjectRef; removeSubject?: SubjectRef }) {
  const r = await admin<Case>('vlpds.admin.updateCase', { body: { id, ...body } })
  modChanged()
  return r
}

export async function createCase(source: string, note?: string, subjects?: SubjectRef[]) {
  const r = await admin<Case>('vlpds.admin.createCase', { body: { source, note: note || undefined, subjects: subjects?.length ? subjects : undefined } })
  modChanged()
  return r
}

export async function moderate(s: SubjectRef, restore: boolean, reason: string, caseId?: string) {
  const r = await admin('vlpds.admin.moderate', {
    body: { did: s.did, kind: s.kind, uri: s.uri, cid: s.cid, action: restore ? 'restore' : 'takedown', reason: reason.trim(), caseId: caseId || undefined },
  })
  modChanged()
  return r
}

export async function setBlobQuota(did: string, v: { bytes?: number; uploadsPerDay?: number; reason?: string }) {
  const r = await admin('vlpds.admin.setBlobQuota', { body: { did, ...v } })
  modChanged()
  return r
}
