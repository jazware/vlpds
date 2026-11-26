// The boards app (packages/boards) wired to the harness stack: the boards
// client's credentials come from the harness's credential chain (local PLC,
// timed XRPC client), and the appview syncs with its own member account and
// takes notifies through a harness NotifyService, the endpoint its
// authorizations register.
import { Appview } from '../../../../boards/src/appview.mjs'
import { BoardsClient as BaseClient } from '../../../../boards/src/client.mjs'
import { signingKey } from '../lib/identity.mjs'
import { spaces } from '../lib/space.mjs'
import { Syncer } from '../lib/syncer.mjs'

export class BoardsClient extends BaseClient {
  constructor(actor, opts = {}) {
    super(actor, { spaces, ...opts })
  }
}

/** The UI's page for a board's at:space/ URI: <ui>/b/<owner DID>/<skey>. */
export const boardLink = (ui, uri) => {
  const p = uri.split('/')
  return `${ui}/b/${p[1]}/${encodeURIComponent(p[3])}`
}

/** The appview with `account` (a read-only member) as its credential source and `svc` as its notify target. */
export function harnessAppview({ account, svc, ...opts }) {
  return new Appview({
    ...opts,
    account,
    svc,
    keyOf: (did) => signingKey(did),
    syncerFor: (board, snapshot) => new Syncer(`appview/${board.split('/')[3]}`, board, account, { snapshot, notify: svc.registration(board) }),
  })
}
