import type { ChipKind, Tone } from '../../components/console/kit'

// The console's one status vocabulary: every entity's state as a tone (colour and glyph) and the
// word the console uses for it, wherever it's shown (a table row, a drawer's chip, a strip, the
// Overview's rail). A page that shows a state takes it from here rather than choosing its own.

export type StatusWord = [ChipKind, string]

/** An account: active, deactivated (or deleting, with a deletion scheduled), taken down, suspended, deleted. */
export function accountTone(a: { status: string; deleteAfter?: string | number | null }): StatusWord {
  switch (a.status) {
    case 'active':
      return ['ok', 'active']
    case 'deactivated':
      return ['warn', a.deleteAfter ? 'deleting' : 'deactivated']
    case 'takendown':
      return ['err', 'taken down']
    case 'suspended':
      return ['err', 'suspended']
    case 'deleted':
      return ['idle', 'deleted']
    default:
      return ['plain', a.status]
  }
}

/** A moderation subject (account, record, blob, space): served, or taken down. */
export const subjectTone = (takenDown: boolean | undefined): StatusWord | undefined =>
  takenDown === undefined ? undefined : takenDown ? ['err', 'taken down'] : ['ok', 'served']

export type CaseStatus = 'open' | 'actioned' | 'dismissed' | 'restored'
/** A case: open waits on someone (warn), actioned took something down (err), restored gave it back (ok), dismissed did nothing (idle). */
export const CASE_TONE: Record<CaseStatus, Tone> = { open: 'warn', actioned: 'err', dismissed: 'idle', restored: 'ok' }

/** An invite code: usable, used up, or disabled. */
export function inviteTone(c: { disabled: boolean; available: number; uses: unknown[] }): StatusWord {
  if (c.disabled) return ['idle', 'disabled']
  if (c.available - c.uses.length <= 0) return ['plain', 'used up']
  return ['ok', 'usable']
}

/** A mail log entry's outcome. */
export function mailStatusTone(status: string): Tone {
  if (status === 'sent' || status === 'logged') return 'ok'
  if (status === 'failed' || status === 'dropped') return 'err'
  if (status === 'suppressed') return 'idle'
  return 'info'
}

/** A firehose connection: live, slow (live and more than 30 s behind), backfilling, or disconnected. */
export function subscriberState(s: { state: string }, slow: boolean, gone = false): StatusWord {
  if (gone) return ['idle', 'disconnected']
  if (s.state === 'backfilling') return ['info', 'backfilling']
  return slow ? ['warn', 'slow'] : ['ok', 'live']
}

/** A relay asked to crawl: not asked yet, accepted the last ask, refused it. */
export function relayTone(status?: { ok: boolean }): Tone {
  return !status ? 'idle' : status.ok ? 'ok' : 'err'
}
