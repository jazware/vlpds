import { admin, XrpcError } from '../xrpc'
import { K } from './keys'
import { mutate, patchAccountRow } from './mutate'
import { hydrate, queryClient, useAdminQuery } from './query'

// Moderation data: the vlpds.admin.* moderation endpoints (src/xrpc/moderation.rs), their
// shapes, their queries and the actions on them.

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
/** An operator change's subject that isn't an account's (audit entries only): a shard, node, served handle domain or cluster setting. */
export type OperatorSubject = { kind: 'shard' | 'node' | 'domain' | 'config'; id: string }
export type AuditSubject = SubjectRef | OperatorSubject
export const isOperatorSubject = (s: AuditSubject): s is OperatorSubject => s.kind === 'shard' || s.kind === 'node' || s.kind === 'domain' || s.kind === 'config'
export type AuditEntry = { id: string; at: string; actor: string; auth?: string; ip?: string; node: string; action: string; subject?: AuditSubject; reason?: string; caseId?: string; detail?: any }
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
export { CASE_TONE } from './status'

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

// ---------------------------------------------------------------- reads

const caseVersion = (c: Case) => c.updatedAt

/** Cases, newest first; each also becomes its own `['case', id]` entry. */
async function fetchCases(p: { status?: string; did?: string; subject?: string }, signal?: AbortSignal) {
  const at = Date.now()
  const r = await admin<{ cases: Case[] }>('vlpds.admin.listCases', { params: p, signal })
  for (const c of r.cases) hydrate(K.case(c.id), c, at, caseVersion)
  return r.cases
}

export const useCases = (p: { status?: string; did?: string; subject?: string } = {}, o: { poll?: number; enabled?: boolean } = {}) =>
  useAdminQuery({ key: K.cases(p), fn: (signal) => fetchCases(p, signal), poll: o.poll ?? 30_000, enabled: o.enabled })

export const useCase = (id: string) =>
  useAdminQuery({ key: K.case(id), fn: (signal) => admin<Case>('vlpds.admin.getCase', { params: { id }, signal }), version: caseVersion })

/** Audit entries, newest first; each also becomes its own `['auditEntry', id]` entry. */
export async function getAuditLog(p: { limit?: number; did?: string; space?: string } = {}, signal?: AbortSignal) {
  const at = Date.now()
  const r = await admin<{ entries: AuditEntry[] }>('vlpds.admin.getAuditLog', { params: p, signal })
  for (const e of r.entries) hydrate(K.auditEntry(e.id), e, at)
  return r.entries
}

export const useAudit = (p: { limit?: number; did?: string; space?: string }, o: { enabled?: boolean } = {}) =>
  useAdminQuery({ key: K.audit(p), fn: (signal) => getAuditLog(p, signal), poll: 60_000, enabled: o.enabled, keep: true })

/** One entry: from any list that held it, else the newest 200. */
export const useAuditEntry = (id: string) =>
  useAdminQuery({
    key: K.auditEntry(id),
    fn: async (signal) => {
      const e = (await getAuditLog({ limit: 200 }, signal)).find((x) => x.id === id)
      if (!e) throw new XrpcError(404, 'NotFound', 'Not among the newest 200 entries.')
      return e
    },
    staleTime: Infinity,
  })

export const useTakedowns = () =>
  useAdminQuery({ key: K.takedowns, fn: (signal) => admin<{ takedowns: TakedownEntry[] }>('vlpds.admin.listTakedowns', { signal }).then((r) => r.takedowns), poll: 30_000 })

export const useOverQuota = () =>
  useAdminQuery({
    key: K.overQuota,
    fn: (signal) => admin<{ accounts: { did: string; bytes: number; limit: number; at: string }[] }>('vlpds.admin.listOverQuota', { signal }).then((r) => r.accounts),
    poll: 120_000,
  })

export const resolveSubject = (q: string) => admin<Resolved>('vlpds.admin.resolveSubject', { params: { q } })
export const useResolved = (q: string) => useAdminQuery({ key: K.resolve(q), fn: () => resolveSubject(q), staleTime: 60_000 })

export const getSubject = (s: { did: string; uri?: string; cid?: string }, signal?: AbortSignal) =>
  admin<SubjectDetail>('vlpds.admin.getSubject', { params: { did: s.did, uri: s.uri, cid: s.cid }, signal })

/** A subject's detail; it sits under its account's key, so any change to the account reaches it. */
export const useSubject = (s: { did: string; uri?: string; cid?: string } | undefined, enabled = true) =>
  useAdminQuery({
    key: K.subject(s?.did ?? '', s?.uri, s?.cid),
    fn: (signal) => getSubject(s!, signal),
    enabled: !!s && enabled,
  })

// ---------------------------------------------------------------- actions

/** Writes a case an action answered with into every cached copy: its own and the lists it belongs in. */
function putCase(c: Case) {
  queryClient.setQueryData(K.case(c.id), c)
  for (const [key, list] of queryClient.getQueriesData<Case[]>({ queryKey: K.cases() })) {
    if (!list) continue
    const p = (key[1] ?? {}) as { status?: string; did?: string; subject?: string }
    const about = !p.did || c.subjects.some((s) => s.did === p.did && (!p.subject || s.uri === p.subject || s.cid === p.subject))
    const fits = (!p.status || p.status === c.status) && about
    const rest = list.filter((x) => x.id !== c.id)
    const had = rest.length !== list.length
    if (fits) queryClient.setQueryData(key, had ? list.map((x) => (x.id === c.id ? c : x)) : [c, ...list])
    else if (had) queryClient.setQueryData(key, rest)
  }
}

export function updateCase(id: string, body: { status?: CaseStatus; note?: string; source?: string; addSubject?: SubjectRef; removeSubject?: SubjectRef }) {
  return mutate({
    run: () => admin<Case>('vlpds.admin.updateCase', { body: { id, ...body } }),
    // a status change is obvious: shown at once, undone if the call fails
    optimistic: body.status
      ? () => {
          const before = queryClient.getQueriesData<Case | Case[]>({ queryKey: K.case(id) }).concat(queryClient.getQueriesData({ queryKey: K.cases() }))
          const c = queryClient.getQueryData<Case>(K.case(id))
          if (c) putCase({ ...c, status: body.status! })
          return () => before.forEach(([k, d]) => queryClient.setQueryData(k, d))
        }
      : undefined,
    write: async (c) => {
      await queryClient.cancelQueries({ queryKey: K.case(id), exact: true })
      putCase(c)
    },
    changes: (c) => [{ kind: 'case', id: c.id }, ...c.subjects.map((s) => ({ kind: 'account', id: s.did }))],
  })
}

export function createCase(source: string, note?: string, subjects?: SubjectRef[]) {
  return mutate({
    run: () => admin<Case>('vlpds.admin.createCase', { body: { source, note: note || undefined, subjects: subjects?.length ? subjects : undefined } }),
    write: (c) => putCase(c),
    changes: (c) => [{ kind: 'case', id: c.id }, ...c.subjects.map((s) => ({ kind: 'account', id: s.did }))],
  })
}

export function moderate(s: SubjectRef, restore: boolean, reason: string, caseId?: string) {
  return mutate({
    run: () =>
      admin('vlpds.admin.moderate', {
        body: { did: s.did, kind: s.kind, uri: s.uri, cid: s.cid, action: restore ? 'restore' : 'takedown', reason: reason.trim(), caseId: caseId || undefined },
      }),
    write: () => {
      if (s.kind === 'account') patchAccountRow(s.did, (r) => ({ ...r, status: restore ? 'active' : 'takendown' }))
    },
    changes: [
      { kind: 'account', id: s.did },
      { kind: 'takedown', id: subjectQuery(s) },
      ...(caseId ? [{ kind: 'case', id: caseId }] : []),
      // a space, or a record in one: the space's page lists its taken-down records
      ...(s.uri?.includes('/space/') ? [{ kind: 'space', id: s.kind === 'space' ? s.uri : spaceRecordParts(s.uri).space }] : []),
    ],
  })
}

export function setBlobQuota(did: string, v: { bytes?: number; uploadsPerDay?: number; reason?: string }) {
  return mutate({
    run: () => admin('vlpds.admin.setBlobQuota', { body: { did, ...v } }),
    changes: [{ kind: 'account', id: did }],
  })
}
