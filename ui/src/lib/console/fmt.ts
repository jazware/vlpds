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
export const factorName = (f: string) => (f === 'second_factor' ? '2FA and recovery codes' : f === 'email_code' ? 'email codes' : f)
