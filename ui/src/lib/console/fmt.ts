// Console formatting on top of lib/format.ts. Everything returns "—" for unknown values.

export { fmtBytes, fmtNum, fmtSi, relTime as ago, seqMillis, seqWriter, short } from '../format'

/** A duration: "42s", "3m 10s", "2h 5m", "4d 1h". */
export function dur(ms: number | undefined): string {
  if (ms === undefined || !isFinite(ms)) return '—'
  const s = Math.max(0, Math.round(ms / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`
}

/** Milliseconds as a latency: "840 µs", "4.2 ms", "152 ms", "1.20 s". */
export function fmtMs(ms: number | undefined | null): string {
  if (ms === undefined || ms === null || !isFinite(ms)) return '—'
  if (ms === 0) return '0 ms'
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`
  if (ms < 10) return `${ms.toFixed(1)} ms`
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

/** Seconds (Prometheus histograms) as a latency. */
export const fmtSec = (s: number | undefined | null) => (s === undefined || s === null ? '—' : fmtMs(s * 1000))

export const fmtPct = (v: number | undefined, digits = 0) => (v === undefined || !isFinite(v) ? '—' : `${v.toFixed(digits)}%`)

export const clock = (ms: number) => new Date(ms).toLocaleTimeString('en-GB', { hour12: false })

/** "did:plc:abcdefgh…wxyz". */
export const shortDid = (d: string) => (d.length > 22 ? `${d.slice(0, 14)}…${d.slice(-4)}` : d)

export const plural = (n: number, w: string, p?: string) => `${n.toLocaleString()} ${n === 1 ? w : (p ?? `${w}s`)}`

/** A factor lock from listLockouts or getAccountSecurity. */
/** How an audited actor got in: a login the proxy verified, a name typed with the admin token, or the moderation service. */
export type AuditAuth = 'proxy' | 'token' | 'service'
export const authName = (a?: string) => (a === 'proxy' ? 'proxy sign-in' : a === 'token' ? 'admin token, name as typed' : a === 'service' ? 'moderation service' : a ? a : 'vlpds')
export const authShort = (a?: string) => (a === 'proxy' ? 'proxy' : a === 'token' ? 'token' : a === 'service' ? 'service' : '')

/** How an audit action reads: its label and its chip's tone (err: removes or takes down, warn: changes access, keys or the cluster, ok: gives back, info: the rest). */
export type AuditTone = 'err' | 'warn' | 'ok' | 'info'
export const AUDIT_ACTIONS: Record<string, { label: string; tone: AuditTone }> = {
  takedown: { label: 'Takedown', tone: 'err' },
  restore: { label: 'Restore', tone: 'ok' },
  'blob.purge': { label: 'Blob purged', tone: 'err' },
  'case.create': { label: 'Case opened', tone: 'info' },
  'case.update': { label: 'Case updated', tone: 'info' },
  'quota.set': { label: 'Quota set', tone: 'info' },
  'second_factors.reset': { label: '2FA reset', tone: 'warn' },
  'sessions.revoke': { label: 'Sessions revoked', tone: 'warn' },
  'app_password.revoke': { label: 'App password revoked', tone: 'warn' },
  'lockout.clear': { label: 'Lockout cleared', tone: 'warn' },
  'space.read': { label: 'Space data read', tone: 'info' },
  'space.registration.remove': { label: 'Registration removed', tone: 'err' },
  'storage.backfill': { label: 'Storage backfill', tone: 'info' },
  'account.create': { label: 'Account created', tone: 'info' },
  'account.handle': { label: 'Handle changed', tone: 'info' },
  'account.email': { label: 'Email changed', tone: 'warn' },
  'account.password': { label: 'Password set', tone: 'warn' },
  'account.signing_key': { label: 'Signing key rotated', tone: 'warn' },
  'account.deactivate': { label: 'Deactivated', tone: 'warn' },
  'account.activate': { label: 'Reactivated', tone: 'ok' },
  'account.delete': { label: 'Account deleted', tone: 'err' },
  'identity.publish': { label: 'Identity published', tone: 'info' },
  'repo.rebuild': { label: 'Repo rebuilt', tone: 'warn' },
  'repo.recount': { label: 'Repo recounted', tone: 'info' },
  'invites.create': { label: 'Invites created', tone: 'info' },
  'invites.disable_account': { label: 'Invites disabled', tone: 'warn' },
  'invites.enable_account': { label: 'Invites enabled', tone: 'ok' },
  'invites.disable_codes': { label: 'Codes disabled', tone: 'warn' },
  'mail.send': { label: 'Mail sent', tone: 'info' },
  'secrets.rewrap': { label: 'Secrets rewrapped', tone: 'warn' },
  'plc.rotate_keys': { label: 'PLC keys rotated', tone: 'warn' },
  'plc.recovery_key': { label: 'Recovery key added', tone: 'warn' },
  'shard.split': { label: 'Shard split', tone: 'warn' },
  'shard.merge': { label: 'Shards merged', tone: 'warn' },
  'shard.abort': { label: 'Reshard aborted', tone: 'err' },
  'feature_level.set': { label: 'Feature level set', tone: 'warn' },
  'firehose.kick': { label: 'Subscriber kicked', tone: 'warn' },
  'crawlers.set': { label: 'Relays changed', tone: 'info' },
  'crawlers.request': { label: 'Crawl requested', tone: 'info' },
  'ratelimits.update': { label: 'Rate limits changed', tone: 'warn' },
  'domain.add': { label: 'Domain added', tone: 'info' },
  'domain.remove': { label: 'Domain removed', tone: 'err' },
}
/** An unknown action (a newer server's) reads as its code, with no tone. */
export const auditAction = (a: string): { label: string; tone?: AuditTone } => AUDIT_ACTIONS[a] ?? { label: a }

/** The cluster settings a `config` audit subject names. */
const CONFIG_NAMES: Record<string, string> = { ratelimits: 'rate limits', crawlers: 'relays', featureLevel: 'feature level' }

/** An audit subject in a few words: whose, or which shard, node, domain or setting. */
export function auditSubjectText(s: { kind: string; did?: string; uri?: string; cid?: string; id?: string }): string {
  if (s.kind === 'shard') return `shard ${s.id}`
  if (s.kind === 'node') return `node ${s.id}`
  if (s.kind === 'domain') return `.${s.id}`
  if (s.kind === 'config') return CONFIG_NAMES[s.id ?? ''] ?? s.id ?? ''
  if (s.kind === 'blob') return `${s.did} ${s.cid}`
  return s.uri ?? s.did ?? ''
}

export const factorName = (f: string) => (f === 'second_factor' ? '2FA and recovery codes' : f === 'email_code' ? 'email codes' : f)
