// The space credential chain, as an app runs it with the reference library:
// a delegation token from the user's own PDS, exchanged at the authority's
// PDS for a credential bound to a fresh P-256 key, then reads anywhere with
// `Authorization: Atproto-Space-Credential`, an audience and an RFC 9421
// signature (@atproto/space createSpaceSigHeaders), plus a MAC request on the
// reads a syncer trusts.
// The chain itself lives in the boards app (packages/boards/src/spaces); this
// wires it to the harness's PLC and its timed XRPC client.
import { COMMIT_MAC_TYPE, RECORD_MAC_TYPE, WANT_MAC_HEADER, encapsulate, formatWantMacHeader, verifyCommit } from '@atproto/space'
import { SpaceCred as BaseCred, Spaces } from '../../../../boards/src/spaces/cred.mjs'
import { SPACE_TYPE } from './env.mjs'
import { makeClient } from './http.mjs'
import { kemKey, pdsEndpoint } from './identity.mjs'

export const spaceUri = (authorityDid, skey, type = SPACE_TYPE) => `at://${authorityDid}/space/${type}/${skey}`
export const spaceDidOf = (uri) => uri.split('/')[2]

export const POLICY = {
  members: (opts = {}) => ({ $type: 'com.atproto.memberspace.policy', ...opts }),
  public: { $type: 'com.atproto.memberspace.policy', publicRead: true },
  managed: (managingApp) => ({ $type: 'com.atproto.managedspace.policy', managingApp }),
  personal: { $type: 'com.atproto.personalspace.policy' },
}

const endpoints = new Map()
/** A repo's host (its #atproto_pds), cached: the harness never moves accounts. */
export async function repoHost(did) {
  if (!endpoints.has(did)) endpoints.set(did, await pdsEndpoint(did))
  return endpoints.get(did)
}

export { decodeJwt } from '../../../../boards/src/spaces/xrpc.mjs'

export const spaces = new Spaces({ repoHost, kemKey, makeClient })

export async function createSpace(authority, skey, opts = {}) {
  const res = await authority.client.com.atproto.space.createSpace({
    spaceType: opts.spaceType ?? SPACE_TYPE,
    skey,
    policy: opts.policy ?? POLICY.members(),
  })
  return res.data.uri
}

export async function putMember(authority, space, member, read = true, write = true) {
  await authority.client.com.atproto.memberspace.putMember({ space, did: member.did ?? member, read, write })
}

/** The delegation token: minted by the user's own PDS for the space. */
export async function delegationToken(actor, space) {
  return spaces.delegationToken(actor.client, space)
}

/** Exchange a delegation token at the authority's PDS (undefined: ask without one). */
export async function exchange(space, token, opts = {}) {
  const c = await spaces.exchange(space, token, opts)
  return new SpaceCred(space, c.credential, c.key)
}

/** A fresh credential for `actor` (delegation on their PDS, exchange at the authority). */
export async function credentialFor(actor, space, opts = {}) {
  return exchange(space, await delegationToken(actor, space), opts)
}

const MAC_TYPES = {
  'com.atproto.space.getLatestCommit': COMMIT_MAC_TYPE,
  'com.atproto.space.getRepo': COMMIT_MAC_TYPE,
  'com.atproto.space.listRepoOps': COMMIT_MAC_TYPE,
  'com.atproto.space.getRecord': RECORD_MAC_TYPE,
}

export class SpaceCred extends BaseCred {
  constructor(space, credential, key) {
    super(space, credential, key, spaces)
  }

  /**
   * A client for `did`'s repo host that asks for a MAC, with a fresh key
   * share, on every method that needs one, and checks none: for callers that
   * want the answer, not its authentication (the cost run, sim bookkeeping).
   */
  async macClient(did) {
    const kem = await kemKey(did)
    const sign = this.signer()
    return makeClient(await repoHost(did), async (req) => {
      await sign(req)
      const type = MAC_TYPES[new URL(req.url).pathname.replace(/^\/xrpc\//, '')]
      if (type) req.headers.set(WANT_MAC_HEADER, formatWantMacHeader(type, (await encapsulate(kem)).keyShare))
    })
  }
}

/** getLatestCommit of `did` with a MAC, verified (throws when it doesn't verify). */
export async function headOf(cred, space, did) {
  const { res, sharedSecret, mac } = await cred.macRead(did, COMMIT_MAC_TYPE, (cl, opts) => cl.com.atproto.space.getLatestCommit({ space, repo: did }, opts))
  const commit = res.data.commit
  if (!mac || !verifyCommit(commit, { space, repo: did, sharedSecret, mac })) throw new Error(`getLatestCommit of ${did}: the commit's MAC did not verify`)
  return commit
}
