// Seeds a small boards board on a real vlpds as the test account and adds a
// member, for trying Spaces by hand. Nothing is cleaned up. Reads the account
// password from ~/.config/vlpds-test-account and never prints it.
//
//   SMOKE_DID=did:plc:… node prod-seed-board.mjs https://pds.example.com <member handle> [skey]
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { oauthLogin } from './lib/oauth.mjs'
import { makeClient } from './lib/http.mjs'

const [BASE = 'https://pds.example.com', MEMBER = 'alice.example.com', SKEY = 'hello'] = process.argv.slice(2)
const TYPE = 'dev.example.boards.board'
const C = { settings: 'dev.example.boards.settings', post: 'dev.example.boards.post', comment: 'dev.example.boards.comment', vote: 'dev.example.boards.vote' }
const acct = Object.fromEntries(
  readFileSync(`${homedir()}/.config/vlpds-test-account`, 'utf8')
    .split('\n')
    .filter((l) => l.includes('='))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]),
)
const plcDoc = (did) => fetch(`https://plc.directory/${did}`).then((r) => r.json())
const resolve = (handle) => fetch(`${BASE}/xrpc/com.atproto.identity.resolveHandle?handle=${handle}`).then((r) => r.json()).then((j) => j.did)

const did = process.env.SMOKE_DID ?? (await resolve(acct.handle))
acct.handle = (await plcDoc(did)).alsoKnownAs?.[0]?.replace('at://', '') ?? acct.handle
const memberDid = MEMBER.startsWith('did:') ? MEMBER : await resolve(MEMBER)
const scope = `atproto space:${TYPE}?authority=*&action=read&action=create&action=update&action=delete&manage=create&manage=update&manage=delete`
const s = await oauthLogin(BASE, { handle: acct.handle, did, password: acct.password, scope })
const c = makeClient(BASE, s.signer())
const now = () => new Date().toISOString()

const space = (
  await c.com.atproto.space.createSpace({ spaceType: TYPE, skey: SKEY, policy: { $type: 'com.atproto.memberspace.policy' } })
).data.uri
console.log('space', space)

const put = (collection, record, rkey) =>
  (rkey ? c.com.atproto.space.putRecord({ space, repo: did, collection, rkey, record: { $type: collection, ...record } }) : c.com.atproto.space.createRecord({ space, repo: did, collection, record: { $type: collection, ...record } })).then((r) => r.data.uri)

const welcome = await put(C.post, {
  title: 'Welcome to the first board on vlpds Spaces',
  body: "This board lives in jaztest's space repo on pds.example.com. Nothing here is on the firehose: members read it with a space credential, and each member's posts live in their own space repo.",
  flair: 'meta',
  createdAt: now(),
})
await put(C.settings, { name: "Jaz's test board", description: 'A private board for trying AT Proto Spaces end to end.', flairs: ['meta', 'question', 'show-and-tell'], pinned: [welcome], createdAt: now() }, 'self')
const q = await put(C.post, { title: 'What should we build on Spaces?', body: 'Private boards work. Group chats, shared lists, private follows? Reply with ideas.', flair: 'question', createdAt: now() })
await put(C.comment, { subject: q, body: 'A private group feed would be a fun first one.', createdAt: now() })
await put(C.vote, { subject: welcome, direction: 'up', createdAt: now() })
await put(C.vote, { subject: q, direction: 'up', createdAt: now() })

await c.com.atproto.memberspace.putMember({ space, did: memberDid, read: true, write: true })
const members = (await c.com.atproto.memberspace.listMembers({ space })).data.members
console.log('members', members.map((m) => `${m.did}${m.write ? ' (read+write)' : ' (read)'}`).join(', '))
const recs = (await c.com.atproto.space.listRecords({ space, repo: did, collection: C.post })).data.records.length
console.log(`seeded: settings, ${recs} posts, 1 comment, 2 votes`)
