import { Chip } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import { auditAction, auditSubjectText } from '../../lib/console/fmt'
import { navigate } from '../../lib/router'

// Audit entries' actions and non-account subjects, as every list of them shows them.

/** The action as a chip with its glyph and label; the code is in the tooltip. */
export function AuditAction({ a }: { a: string }) {
  const { label, tone } = auditAction(a)
  return tone ? (
    <Chip k={tone} title={a}>
      {label}
    </Chip>
  ) : (
    <span className="mono sm">{a}</span>
  )
}

type OperatorSubject = { kind: 'shard' | 'node' | 'domain' | 'config'; id: string }

const CONFIG_PAGE: Record<string, string> = { ratelimits: '/admin/limits', crawlers: '/admin/firehose', featureLevel: '/admin/nodes' }

/** Where a shard, node, domain or setting is shown: its slide-over, or its page. */
function openOperatorSubject(s: OperatorSubject) {
  if (s.kind === 'node') openPanel('node', s.id)
  else if (s.kind === 'domain') openPanel('domain', s.id)
  else if (s.kind === 'shard') navigate('/admin/nodes')
  else navigate(CONFIG_PAGE[s.id] ?? '/admin/config')
}

export function OperatorSubjectLink({ s }: { s: OperatorSubject }) {
  return (
    <button type="button" className="cxp-link mono" onClick={() => openOperatorSubject(s)}>
      {auditSubjectText(s)}
    </button>
  )
}

/** What else an entry points at: the mail log for a message, the config's history for a rate-limit change. */
export function auditLinks(e: { action: string; subject?: { kind: string; did?: string }; detail?: any }): [string, string][] {
  const did = e.subject?.kind === 'account' ? e.subject.did : undefined
  if (e.action === 'mail.send' && did) return [[`/admin/mail?did=${encodeURIComponent(did)}`, 'Mail log for this account']]
  if (e.action === 'ratelimits.update' && e.detail?.version != null) return [['/admin/limits', `Version ${e.detail.version} in the rate-limit history`]]
  return []
}
