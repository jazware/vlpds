import type { ReactNode } from 'react'
import { detailKind } from '../../components/console/Drawer'
import { openPanel } from '../../components/console/nav'
import { useHandle } from '../../lib/console/firehose'
import { shortDid } from '../../lib/console/fmt'
import { navigate } from '../../lib/router'
import '../../console-people.css'

// Small parts the Moderation, Limits and Domains sections share.

/** An account's own slide-over when the Accounts section registers one, else its page. */
export function openAccount(did: string) {
  if (detailKind('account')) openPanel('account', did)
  else navigate(`/admin/accounts/${encodeURIComponent(did)}`)
}

/** @handle (looked up in batches), or the DID shortened until it's known. */
export function Who({ did, handle }: { did: string; handle?: string | null }) {
  const h = useHandle(handle ? undefined : did)
  const v = handle || h
  return v ? (
    <span className="cx-handle" title={did}>
      @{v}
    </span>
  ) : (
    <span className="cx-did" title={did}>
      {shortDid(did)}
    </span>
  )
}

/** An account, as a link to it. */
export function AccountLink({ did, handle }: { did: string; handle?: string | null }) {
  return (
    <button
      type="button"
      className="cxp-link"
      onClick={(e) => {
        e.stopPropagation()
        openAccount(did)
      }}
    >
      <Who did={did} handle={handle} />
    </button>
  )
}

/** One action in a drawer: what it does on the left, its button on the right. */
export function ActRow({ title, children, button }: { title: ReactNode; children?: ReactNode; button: ReactNode }) {
  return (
    <div className="cx-act">
      <div className="ad">
        <b>{title}</b>
        {children}
      </div>
      {button}
    </div>
  )
}
