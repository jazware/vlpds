// A space syncer built on the reference library: the boards app's
// SpaceSyncer (packages/boards/src/spaces/syncer.mjs), with credentials from a
// harness member account's delegation and KEM keys from the local PLC.
import { SpaceSyncer, hashEq } from '../../../../boards/src/spaces/syncer.mjs'
import { attempt } from './http.mjs'
import { credentialFor } from './space.mjs'

export { hashEq }

export class Syncer extends SpaceSyncer {
  /** `member`: the account whose delegation the syncer's credentials come from (a reader). */
  constructor(name, space, member, { snapshot } = {}) {
    super(name, space, { mint: () => credentialFor(member, space), attempt, snapshot })
    this.member = member
  }
}
