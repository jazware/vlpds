// The local PLC: resolve DID documents (no caching: the harness edits them),
// mint service DIDs for syncers, and add service entries to accounts whose
// rotation key the harness holds (the reference PDSes' and vlpds's dev keys).
import * as plc from '@did-plc/lib'
import { Secp256k1Keypair } from '@atproto/crypto'
import { URLS, REF_ROTATION_KEYS, VLPDS_ROTATION_KEY } from './env.mjs'

const client = new plc.Client(URLS.plc)

export async function resolveDid(did) {
  const r = await fetch(`${URLS.plc}/${did}`)
  if (!r.ok) throw new Error(`resolve ${did}: ${r.status}`)
  return r.json()
}

export async function plcData(did) {
  const r = await fetch(`${URLS.plc}/${did}/data`)
  if (!r.ok) throw new Error(`plc data ${did}: ${r.status}`)
  return r.json()
}

function service(doc, id) {
  return doc.service?.find((s) => s.id === `#${id}` || s.id === `${doc.id}#${id}`)
}

/** The account's `#<id>` verification method as a did:key. */
export async function didKey(did, id) {
  const doc = await resolveDid(did)
  const vm = doc.verificationMethod?.find((m) => m.id === `#${id}` || m.id === `${did}#${id}`)
  if (!vm) throw new Error(`${did}: no #${id} key`)
  return `did:key:${vm.publicKeyMultibase}`
}

/** The `#atproto` signing key. */
export const signingKey = (did) => didKey(did, 'atproto')

/** The `#atproto_kem` key a syncer encapsulates MAC secrets to. */
export const kemKey = (did) => didKey(did, 'atproto_kem')

/** The account's PDS, which is also where a space authority hosts its spaces. */
export async function pdsEndpoint(did) {
  const doc = await resolveDid(did)
  return service(doc, 'atproto_pds')?.serviceEndpoint
}

/** A fresh did:plc for a service (a syncer) with one service entry. */
export async function createServiceDid(serviceId, endpoint) {
  const key = await Secp256k1Keypair.create({ exportable: true })
  const op = await plc.signOperation(
    {
      type: 'plc_operation',
      rotationKeys: [key.did()],
      alsoKnownAs: [],
      verificationMethods: { atproto: key.did() },
      services: { [serviceId]: { type: 'AtprotoSpaceService', endpoint } },
      prev: null,
    },
    key,
  )
  const did = await plc.didForCreateOp(op)
  await client.sendOperation(did, op)
  return { did, key, serviceRef: `${did}#${serviceId}` }
}

async function rotationKeypair(hostKey) {
  const hex = hostKey === 'vlpds' ? VLPDS_ROTATION_KEY : REF_ROTATION_KEYS[hostKey]
  return Secp256k1Keypair.import(hex)
}

/**
 * Set (or with endpoint null, remove) a service entry on an account's DID
 * document, signed with its host's rotation key, which the harness holds.
 */
export async function setService(did, hostKey, id, type, endpoint) {
  const key = await rotationKeypair(hostKey)
  const last = await client.getLastOp(did)
  const op = await plc.createUpdateOp(last, key, (normalized) => {
    const services = { ...normalized.services }
    if (endpoint) services[id] = { type, endpoint }
    else delete services[id]
    return { ...normalized, services }
  })
  await client.sendOperation(did, op)
}
