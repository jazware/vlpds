// Stored data across the upgrade to this build: an older vlpds (OLD_VLPDS_BIN,
// a Nov 17 alpha build such as v1.4.0) writes spaces on the old wire, stops,
// and this build starts on the same bucket prefix and serves them on the new
// one. The old phase talks raw XRPC with space URIs in the form before the Nov
// 24 alpha (`at://{did}/space/...`) and reads only as the repos' owners; the
// new phase names the same spaces in the current form (`at:space/{did}/...`)
// and reads and writes with the reference library.
//
//   OLD_VLPDS_BIN=<binary> bench/spaces/run.sh migrate     (just spaces-migrate)
import { verifyRecord, verifyRepoStarFull, RECORD_MAC_PROFILE, COMMIT_MAC_PROFILE } from '@atproto/space'
import { Actor, RUN } from './lib/actor.mjs'
import { COLL, PORTS, VLPDS_ADMIN_TOKEN, log } from './lib/env.mjs'
import { attempt, hfetch, rawXrpc, waitFor } from './lib/http.mjs'
import { NOTIFY, NotifyService } from './lib/notifysvc.mjs'
import { Report } from './lib/report.mjs'
import { credentialFor, headOf, putMember } from './lib/space.mjs'
import { Vlpds } from './lib/vlpds.mjs'

const OLD = process.env.OLD_VLPDS_BIN
const WRITE = 'com.atproto.space.defs#repoWrite'
/** `at://{did}/space/{rest}` as `at:space/{did}/{rest}`. */
const current = (uri) => uri.replace(/^at:\/\/([^/]+)\/space\//, 'at:space/$1/')
const record = (text, extra = {}) => ({ $type: COLL, text, createdAt: new Date().toISOString(), ...extra })

/** An OAuth (DPoP) call as `actor`, whatever the lexicons say: `{status, ok, json, error}`. */
async function call(actor, nsid, { method = 'POST', params, body } = {}) {
  const sign = actor.oauth.signer()
  const u = new URL(`/xrpc/${nsid}`, actor.base)
  for (const [k, v] of Object.entries(params ?? {})) u.searchParams.set(k, String(v))
  for (let i = 0; i < 3; i++) {
    const headers = new Headers()
    await sign({ method, url: u.toString(), headers })
    if (body !== undefined) headers.set('content-type', 'application/json')
    const res = await hfetch(u, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    if (i < 2 && (await sign.retry(res))) continue
    const text = await res.text()
    let json
    try {
      json = JSON.parse(text)
    } catch {}
    return { status: res.status, ok: res.ok, json, error: json?.error, message: json?.message }
  }
}

async function must(actor, nsid, opts) {
  const r = await call(actor, nsid, opts)
  if (!r.ok) throw new Error(`${nsid} as ${actor}: ${r.status} ${r.error} ${r.message}`)
  return r.json
}

/** What the owner reads of its repo in `space`: head rev and path -> cid. */
async function ownerView(actor, space) {
  const head = await must(actor, 'com.atproto.space.getLatestCommit', { method: 'GET', params: { space, repo: actor.did } })
  const paths = {}
  let cursor
  do {
    const r = await must(actor, 'com.atproto.space.listRecords', { method: 'GET', params: { space, repo: actor.did, limit: 100, ...(cursor ? { cursor } : {}) } })
    for (const rec of r.records) paths[`${rec.collection}/${rec.rkey}`] = rec.cid
    cursor = r.cursor
  } while (cursor)
  return { rev: head.commit.rev, paths }
}

/** The old build writes: two spaces, three writers, a removed writer, a blob and a deleted space. */
async function oldPhase(prefix) {
  const vl = await new Vlpds({ prefix, bin: OLD }).start()
  try {
    const [alice, bob, dave] = [await Actor.create('vlpds', 'alice'), await Actor.create('vlpds', 'bob'), await Actor.create('vlpds', 'dave')]
    const mk = async (skey) =>
      (await must(alice, 'com.atproto.space.createSpace', { body: { spaceType: 'com.example.group', skey, policy: { $type: 'com.atproto.memberspace.policy' } } })).space
    const kept = await mk(`kept${RUN}`)
    const gone = await mk(`gone${RUN}`)
    if (!kept.startsWith('at://')) throw new Error(`the old build should name spaces in the old form: ${kept}`)
    for (const [space, who] of [[kept, bob], [kept, dave], [gone, bob]]) {
      await must(alice, 'com.atproto.memberspace.putMembers', { body: { space, members: [{ did: who.did, read: true, write: true }] } })
    }
    const write = (who, space, rkey, rec) => must(who, 'com.atproto.space.createRecord', { body: { space, repo: who.did, collection: COLL, rkey, record: rec } })
    const blobBytes = Buffer.from(`migrated space blob ${RUN}`)
    const up = await alice.client.com.atproto.repo.uploadBlob(blobBytes, { encoding: 'text/plain' })
    for (const k of ['a1', 'a2']) await write(alice, kept, k, record(`alice ${k}`))
    await write(alice, kept, 'a3', record('alice with blob', { file: up.data.blob }))
    for (const k of ['b1', 'b2', 'b3']) await write(bob, kept, k, record(`bob ${k}`))
    await must(bob, 'com.atproto.space.deleteRecord', { body: { space: kept, repo: bob.did, collection: COLL, rkey: 'b1' } })
    await write(dave, kept, 'd1', record('dave'))
    await write(alice, gone, 'g1', record('alice in gone'))
    await write(bob, gone, 'g2', record('bob in gone'))
    // dave's notify reaching the authority first, so his removal has a writer to remove
    await new Promise((r) => setTimeout(r, 1500))
    await must(alice, 'com.atproto.memberspace.removeMembers', { body: { space: kept, dids: [dave.did] } })
    await must(alice, 'com.atproto.space.removeWriter', { body: { space: kept, repo: dave.did } })
    await must(alice, 'com.atproto.space.deleteSpace', { body: { space: gone } })
    // the last writes may still be in the outbox at the stop: this build delivers them
    const before = { alice: await ownerView(alice, kept), bob: await ownerView(bob, kept) }
    log(`old build wrote ${kept} (alice ${before.alice.rev}, bob ${before.bob.rev}) and deleted ${gone}`)
    return { alice, bob, dave, kept: current(kept), gone: current(gone), oldKept: kept, before, blob: { cid: up.data.blob.ref.toString(), bytes: blobBytes } }
  } finally {
    await vl.stop()
  }
}

async function main() {
  if (!OLD) throw new Error('OLD_VLPDS_BIN is not set: the older vlpds binary that writes the data')
  const rep = new Report(process.env.REPORT ?? 'migrate', { run: RUN, old: OLD, vlpds: process.env.VLPDS_REV ?? '?' })
  const prefix = `migrate-${Date.now().toString(36)}`
  const cfg = 'old→new'
  let S
  await rep.step(cfg, 'old build writes', async () => {
    S = await oldPhase(prefix)
  })
  const svc = await new NotifyService(PORTS.syncer).start()
  const vl = await new Vlpds({ prefix }).start()
  try {
    const step = (name, fn) => rep.step(cfg, name, fn, { needs: ['old build writes'] })
    const { alice, bob, dave, kept, gone, before } = S ?? {}

    await step('old form refused', async (check) => {
      const r = await call(alice, 'com.atproto.space.getSpace', { method: 'GET', params: { space: S.oldKept } })
      check(r.status === 400 && r.error === 'InvalidRequest', 'getSpace refuses the space in the old form', `${r.status} ${r.error}`)
    })

    await step('owner reads', async (check) => {
      for (const [name, who] of [['alice', alice], ['bob', bob]]) {
        const now = await ownerView(who, kept)
        check(now.rev === before[name].rev, `${name}'s head rev unchanged`, `${now.rev} vs ${before[name].rev}`)
        check(JSON.stringify(now.paths) === JSON.stringify(before[name].paths), `${name}'s records unchanged`, JSON.stringify(now.paths))
      }
    })

    await step('space and members', async (check) => {
      const sp = await alice.client.com.atproto.space.getSpace({ space: kept })
      check(sp.data.space === kept, 'getSpace names the space', JSON.stringify(sp.data))
      const m = await alice.client.com.atproto.memberspace.listMembers({ space: kept })
      const dids = m.data.members.map((x) => x.did)
      check(dids.includes(bob.did) && !dids.includes(dave.did), 'bob is a member, dave is not', JSON.stringify(dids))
      const ls = await alice.client.com.atproto.space.listSpaces({ spaceType: 'com.example.group' })
      check(ls.data.spaces.some((x) => x.space === kept), 'listSpaces lists the kept space', JSON.stringify(ls.data.spaces))
    })

    let cred
    await step('writer set', async (check) => {
      cred = await credentialFor(bob, kept)
      const host = await cred.repoClient(alice.did)
      const lw = await waitFor('both writers at their old heads', async () => {
        const r = await host.com.atproto.space.listWriters({ space: kept })
        const at = (who) => r.data.repos.find((e) => e.repo === who.did)
        const done = at(alice)?.repoRev === before.alice.rev && at(bob)?.repoRev === before.bob.rev
        return done && r.data
      }, { timeoutMs: 30_000 })
      const entries = lw.repos.filter((e) => e.$type === WRITE)
      check(!entries.some((e) => e.repo === dave.did), 'the writer the old build removed is not listed', JSON.stringify(lw.repos))
      check(entries.every((e) => typeof e.spaceRev === 'string' && e.data), 'every entry has its spaceRev and digest', JSON.stringify(entries))
    })

    await step('MACs and STAR', async (check) => {
      for (const who of [alice, bob]) {
        const head = await headOf(cred, kept, who.did)
        check(head.rev === before[who === alice ? 'alice' : 'bob'].rev, `${who.name}'s commit MAC verifies at the old head`)
        const { res, mac } = await cred.macRead(who.did, COMMIT_MAC_PROFILE, (cl, opts) => cl.com.atproto.space.getRepo({ space: kept, repo: who.did }, opts))
        const ok = await verifyRepoStarFull([Buffer.from(res.data)], { space: kept, repo: who.did, ...mac }).then(() => true, (e) => e.message)
        check(ok === true, `${who.name}'s getRepo STAR verifies`, ok)
      }
      const { res, mac } = await cred.macRead(alice.did, RECORD_MAC_PROFILE, (cl, opts) => cl.com.atproto.space.getRecord({ space: kept, repo: alice.did, collection: COLL, rkey: 'a1' }, opts))
      const rec = { uri: res.data.uri, cid: String(res.data.cid), value: res.data.value }
      const ok = await Promise.resolve()
        .then(() => verifyRecord(rec, { uri: res.data.uri, ...mac }))
        .then(() => true, (e) => e.message)
      check(ok === true, 'a record written by the old build verifies with its record MAC', ok)
    })

    await step('blobs', async (check) => {
      const cl = await cred.repoClient(alice.did)
      const lb = await cl.com.atproto.space.listBlobs({ space: kept, repo: alice.did })
      check(lb.data.cids.includes(S.blob.cid), 'listBlobs lists the old blob', JSON.stringify(lb.data.cids))
      const got = await cl.com.atproto.space.getBlob({ space: kept, repo: alice.did, cid: S.blob.cid })
      check(Buffer.from(got.data).equals(S.blob.bytes), 'getBlob returns its bytes')
    })

    await step('new writes on old repos', async (check) => {
      const host = await cred.repoClient(alice.did)
      const old = (await host.com.atproto.space.listWriters({ space: kept })).data.repos
      const maxOld = old.map((e) => e.spaceRev).sort().pop()
      const notify = svc.registration(kept)
      const synced = await credentialFor(bob, kept, { notify })
      check(typeof synced.spaceRev === 'string', 'authorizeSpaceSync answers the space rev', String(synced.spaceRev))
      const r = await bob.client.com.atproto.space.createRecord({ space: kept, repo: bob.did, collection: COLL, rkey: 'b4', record: record('bob after the upgrade') })
      const head = await headOf(cred, kept, bob.did)
      const e = await waitFor('bob at his new head', async () => {
        const lw = await host.com.atproto.space.listWriters({ space: kept })
        return lw.data.repos.find((x) => x.repo === bob.did && x.repoRev === head.rev)
      }, { timeoutMs: 20_000 })
      check(e.spaceRev > maxOld, 'the new write sequences after every old one', `${e.spaceRev} vs ${maxOld}`)
      check(r.data.cid, 'createRecord answers a cid')
      const u = await waitFor('the syncer told of it', async () =>
        svc.callsTo(NOTIFY, kept).map((c) => c.body.update).find((x) => x?.$type === WRITE && x.repo === bob.did && x.repoRev === head.rev),
      )
      check(u.spaceRev === e.spaceRev, 'notifySpaceUpdate carries the same spaceRev', JSON.stringify(u))
    })

    await step('member from another host', async (check) => {
      const carol = await Actor.create('ref-a', 'carol')
      await putMember(alice, kept, carol)
      await carol.client.com.atproto.space.createRecord({ space: kept, repo: carol.did, collection: COLL, rkey: 'c1', record: record('carol') })
      const host = await cred.repoClient(alice.did)
      const e = await waitFor('carol in the writer set', async () => {
        const lw = await host.com.atproto.space.listWriters({ space: kept })
        return lw.data.repos.find((x) => x.repo === carol.did)
      }, { timeoutMs: 30_000 })
      check(e.$type === WRITE, "carol's notifyRepoUpdate lands at the migrated space", JSON.stringify(e))
    })

    await step('deleted space', async (check) => {
      const r = await attempt(() => credentialFor(bob, gone))
      check(!r.ok && r.error === 'SpaceDeleted', 'authorizeSpaceSync of the space the old build deleted answers SpaceDeleted', `${r.status} ${r.error}`)
    })

    await step('checkSpace', async (check) => {
      for (const who of [alice, bob]) {
        const r = await rawXrpc(vl.nodes[0].url, 'vlpds.admin.checkSpace', {
          params: { did: who.did, space: kept, reason: 'migration check' },
          headers: { authorization: `Basic ${Buffer.from(`admin:${VLPDS_ADMIN_TOKEN}`).toString('base64')}` },
        })
        check(r.ok && r.json?.ok === true, `checkSpace of ${who.name}'s repo is clean`, JSON.stringify(r.json).slice(0, 400))
      }
    })
  } finally {
    const path = rep.write()
    log(`report: ${path}`)
    await svc.stop()
    await vl.stop()
  }
  console.log(`\n${rep.markdown()}`)
  process.exit(rep.failed().length || rep.rows.some((r) => r.status === 'blocked') ? 1 : 0)
}

main().catch((e) => {
  console.error(e)
  process.exit(2)
})
