// Spaces migration e2e (README.md "Spaces"): accounts with space repos move
// to a local vlpds through /migrate in headless Chromium, the Spaces step's
// OAuth sign-ins included, then every moved repo is checked on vlpds with
// the reference library (@atproto/space readRepoStar: the records fold to the
// commit's data). A space the account runs moves too (its meta first).
//
//   alice: reference PDS (Spaces alpha) -> vlpds, simple mode
//   erin:  another vlpds -> vlpds, advanced mode
//
// Run by spaces.sh, which starts the stack. Every URL is local.

import { chromium } from 'playwright'
import { createHash, randomBytes } from 'node:crypto'
import { deflateSync } from 'node:zlib'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { readRepoStar } from '@atproto/space'
import { hostUrl, oauthLogin } from './lib/oauth.mjs'

const REF = process.env.REF_SPACES ?? 'http://localhost:2786'
const VLPDS = process.env.VLPDS ?? 'http://127.0.0.1:2787'
const SRC = process.env.SRC_VLPDS ?? 'http://localhost:2788'
const PLC = process.env.PLC ?? 'http://127.0.0.1:2782'
const MAIL = process.env.MAILPIT ?? 'http://127.0.0.1:2785'
const ADMIN = process.env.VLPDS_ADMIN ?? 'dev-admin-token'
const OUT = new URL('./out/spaces/', import.meta.url).pathname
const HEADED = !!process.env.HEADED
const TYPE = 'com.example.group'
const COLL = 'com.example.spaceRecord'

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let failures = 0
function check(ok, what, detail = '') {
  if (ok) log(`  ok   ${what}`)
  else {
    failures++
    log(`  FAIL ${what} ${detail}`)
  }
}

async function xrpc(base, nsid, { params, body, auth, bytes, type } = {}) {
  const q = params ? `?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined))}` : ''
  const headers = {}
  if (auth) headers.authorization = auth.startsWith('Basic') ? auth : `Bearer ${auth}`
  let payload
  if (bytes) {
    payload = bytes
    headers['content-type'] = type
  } else if (body !== undefined) {
    payload = JSON.stringify(body)
    headers['content-type'] = 'application/json'
  }
  const r = await fetch(hostUrl(`${base}/xrpc/${nsid}${q}`), { method: payload !== undefined ? 'POST' : 'GET', headers, body: payload })
  const buf = Buffer.from(await r.arrayBuffer())
  if (!r.ok) {
    let j = {}
    try {
      j = JSON.parse(buf.toString())
    } catch {}
    const e = new Error(`${nsid} ${r.status} ${j.error ?? ''} ${j.message ?? buf.toString().slice(0, 200)}`)
    e.status = r.status
    e.error = j.error
    throw e
  }
  return (r.headers.get('content-type') ?? '').includes('json') ? JSON.parse(buf.toString() || '{}') : buf
}
const basic = `Basic ${Buffer.from(`admin:${ADMIN}`).toString('base64')}`

// ---------------------------------------------------------------- mail

/** The reference PDS's email token (Mailpit). */
async function mailToken(to, since) {
  for (let i = 0; i < 60; i++) {
    const r = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}&limit=20`).then((r) => r.json())
    const m = (r.messages ?? []).find((m) => Date.parse(m.Created) >= since - 2000)
    if (m) {
      const full = await fetch(`${MAIL}/api/v1/message/${m.ID}`).then((r) => r.json())
      const tok = (full.Text ?? '').match(/\b([A-Za-z0-9]{5}-[A-Za-z0-9]{5})\b/)
      if (tok) return tok[1]
    }
    await sleep(500)
  }
  throw new Error(`no mail to ${to}`)
}

/** A vlpds (dev mode) email token, once it differs from `before`. */
async function devMailToken(base, email, before) {
  for (let i = 0; i < 60; i++) {
    const r = await xrpc(base, 'vlpds.admin.getDevMail', { auth: basic, params: { email } })
    if (r.token && r.token !== before) return r.token
    await sleep(250)
  }
  throw new Error(`no dev mail token for ${email} at ${base}`)
}

// ---------------------------------------------------------------- a real PNG

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  return c >>> 0
})
function crc32(buf) {
  let c = 0xffffffff
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}
function chunk(type, data) {
  const len = Buffer.alloc(4)
  len.writeUInt32BE(data.length)
  const td = Buffer.concat([Buffer.from(type), data])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(td))
  return Buffer.concat([len, td, crc])
}
function png(seed) {
  const w = 32
  const raw = Buffer.alloc((w * 3 + 1) * w)
  const s = createHash('sha256').update(String(seed)).digest()
  for (let i = 0; i < raw.length; i++) raw[i] = i % (w * 3 + 1) === 0 ? 0 : s[i % 32] ^ (i & 0xff)
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(w, 0)
  ihdr.writeUInt32BE(w, 4)
  ihdr[8] = 8
  ihdr[9] = 2
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))])
}
const sha = (b) => createHash('sha256').update(b).digest('hex')

// ---------------------------------------------------------------- seed

const RUN = randomBytes(2).toString('hex')
const spaceUri = (authority, skey) => `at://${authority}/space/${TYPE}/${skey}`
const MEMBERS = { $type: 'com.atproto.memberspace.policy' }
// what the seed's apps ask of a vlpds: spaces of the test type, managed and written, and blobs
const SEED_SCOPE = `atproto space:${TYPE}?authority=*&collection=*&action=read&action=read_self&action=create&manage=create&manage=update blob:*/*`

/** An account and the client its space calls go through: a password session on the reference, OAuth on vlpds. */
async function account(base, name, domain, { oauth }) {
  const handle = `${name}${RUN}.${domain}`
  const password = randomBytes(12).toString('base64url')
  const email = `${name}${RUN}@example.com`
  const r = await xrpc(base, 'com.atproto.server.createAccount', { body: { handle, password, email } })
  const a = { name, base, handle, password, email, did: r.did, jwt: r.accessJwt }
  if (oauth) {
    const s = await oauthLogin(base, { handle, did: a.did, password, scope: SEED_SCOPE })
    a.call = (nsid, o = {}) => s.xrpc(nsid, o)
  } else {
    a.call = (nsid, o = {}) => xrpc(base, nsid, { ...o, auth: a.jwt })
  }
  return a
}

async function createSpace(a, skey) {
  const out = await a.call('com.atproto.space.createSpace', { body: { spaceType: TYPE, skey, policy: MEMBERS } })
  return out.uri
}

async function writeRecords(a, space, n, withBlob) {
  for (let i = 0; i < n; i++) {
    const record = { $type: COLL, text: `${a.name} in ${space.split('/').pop()} #${i}`, createdAt: new Date().toISOString() }
    if (withBlob && i === 0) {
      const bytes = png(`${a.did}-${space}`)
      const up = await a.call('com.atproto.repo.uploadBlob', { bytes, type: 'image/png' })
      record.image = up.blob
      a.blobs[up.blob.ref.$link] = sha(bytes)
    }
    await a.call('com.atproto.space.createRecord', { body: { space, repo: a.did, collection: COLL, record } })
  }
}

const didKeys = async (did) => (await fetch(`${PLC}/${did}/data`).then((r) => r.json())).verificationMethods

/** The account's own repo as its host serves it (an OAuth read: no MAC), its records checked against the commit's data. */
async function verifiedRepo(star, space, did) {
  const v = await readRepoStar([new Uint8Array(star)])
  const records = []
  for await (const r of v.records) records.push(`${r.collection}/${r.rkey} ${r.cid.toString()}`)
  if (v.commit.repo !== did || v.commit.space !== space) throw new Error(`getRepo answered ${v.commit.repo} in ${v.commit.space}`)
  return { rev: v.commit.rev, data: Buffer.from(v.commit.data).toString('hex'), records: records.sort() }
}

async function seed() {
  log('seed')
  // on the reference PDS: owner governs "club", alice is a member and writes there, and in "notes" of her own
  const owner = await account(REF, 'owner', 'test', { oauth: false })
  const alice = await account(REF, 'alice', 'test', { oauth: false })
  // on the source vlpds: the same shape, through OAuth
  const frank = await account(SRC, 'frank', 'src.test', { oauth: true })
  const erin = await account(SRC, 'erin', 'src.test', { oauth: true })
  for (const [gov, member, base] of [
    [owner, alice, REF],
    [frank, erin, SRC],
  ]) {
    member.blobs = {}
    const club = await createSpace(gov, 'club')
    await gov.call('com.atproto.memberspace.putMember', { body: { space: club, did: member.did, read: true, write: true } })
    const notes = await createSpace(member, 'notes')
    await writeRecords(member, club, 3, false)
    await writeRecords(member, notes, 4, true)
    // a public post too, so the ordinary copy has something
    await xrpc(base, 'com.atproto.repo.createRecord', {
      auth: member.jwt,
      body: { repo: member.did, collection: 'app.bsky.feed.post', record: { $type: 'app.bsky.feed.post', text: 'moving soon', createdAt: new Date().toISOString() } },
    })
    member.spaces = [club, notes]
    member.oldKeys = await didKeys(member.did)
    member.before = {}
    for (const s of member.spaces) {
      const star = await member.call('com.atproto.space.getRepo', { params: { space: s, repo: member.did }, raw: true })
      member.before[s] = await verifiedRepo(star, s, member.did)
    }
    member.members = (await member.call('com.atproto.memberspace.listMembers', { params: { space: notes } })).members
    log(`  ${member.handle}: ${member.spaces.length} spaces, ${Object.values(member.before).reduce((n, r) => n + r.records.length, 0)} records, ${Object.keys(member.blobs).length} blob`)
  }
  return { alice, erin }
}

// ---------------------------------------------------------------- drive

let shotN = 0
async function shot(page, name) {
  mkdirSync(`${OUT}shots`, { recursive: true })
  await page.screenshot({ path: `${OUT}shots/${String(++shotN).padStart(2, '0')}-${name}.png`, fullPage: true })
}
const heading = (page, re, timeout = 60_000) => page.locator('.mig-card h1', { hasText: re }).waitFor({ timeout })
const flat = (s) => s.replace(/\s+/g, ' ').trim()
const JARGON = /\b(PLC|DIDs?|did:\w*|repo|repository|CAR|blobs?|rotation keys?|service auth|PDS|OAuth)\b/

/** On an authorization page (the reference's or a vlpds's): sign in if asked, then allow. */
async function authorize(page, a, name) {
  await page.waitForURL((u) => u.pathname.startsWith('/oauth/authorize'), { timeout: 30_000 })
  await shot(page, `${name}-authorize`)
  const host = new URL(page.url()).host
  if (/:2786$/.test(host)) {
    // the reference's authorization UI (a React app)
    const pw = page.locator('input[type=password]')
    await pw.waitFor({ timeout: 30_000 })
    const id = page.locator('input[name=username], input[name=identifier]').first()
    if ((await id.count()) && !(await id.inputValue())) await id.fill(a.handle)
    await pw.fill(a.password)
    await page.getByRole('button', { name: /^(Sign in|Next)$/i }).click()
    await page.getByRole('button', { name: /^(Accept|Authorize|Allow)$/i }).click({ timeout: 30_000 })
  } else {
    if (await page.getByText('Choose an account').count()) await page.click('button:has-text("Use another account")')
    if (await page.locator('input#password').count()) {
      const id = page.locator('input#identifier')
      if ((await id.count()) && !(await id.inputValue())) await id.fill(a.handle)
      await page.fill('input#password', a.newPassword ?? a.password)
      await page.click('button[value=sign-in]')
    }
    await page.locator('button[value=allow]').waitFor({ timeout: 30_000 })
    await shot(page, `${name}-consent`)
    await page.click('button[value=allow]')
  }
  await page.waitForURL((u) => u.pathname === '/migrate', { timeout: 30_000 })
}

async function drive(ctx, a, oldBase, { advanced, loseImport }) {
  log(`drive: ${a.handle} from ${oldBase}, ${advanced ? 'advanced' : 'simple'} mode`)
  const page = await ctx.newPage()
  page.on('pageerror', (e) => log(`  [pageerror] ${e.message}`))
  page.on('console', (m) => m.type() === 'error' && log(`  [console] ${m.text()}`))
  const imports = []
  const metaImports = []
  page.on('request', (r) => {
    if (r.url().includes('/xrpc/com.atproto.space.importRepo')) imports.push(r.url())
    if (r.url().includes('/xrpc/com.atproto.space.importSpaceMeta')) metaImports.push(r.url())
  })
  await page.goto(`${VLPDS}/migrate`)
  await heading(page, /Move your account here/)
  if (advanced) await page.check('input[name=advanced]')
  await page.fill('input[name=identifier]', a.did)
  await page.click('button:has-text("Find my account")')
  await heading(page, /Sign in to/)
  await page.fill('input[name=password]', a.password)
  await page.click('button:has-text("Sign in")')
  await heading(page, advanced ? /Pre-flight checks/ : /Checking your account/)
  for (let i = 0; (await page.locator('.mig-check .spinner').count()) > 0; i++) {
    if (i > 150) throw new Error('preflight checks never finished')
    await sleep(200)
  }
  await page.click('button:has-text("Continue")')
  await heading(page, /Choose your handle/)
  const name = `${a.name}${RUN}`
  await page.fill('input[name=handle]', name)
  await page.getByText(/is available/).waitFor()
  await page.click('button:has-text("Continue")')
  a.newHandle = `${name}.vlpds.test`
  await heading(page, /Create @/)
  await page.click('button:has-text("Create my account here")')
  await heading(page, /Save a copy of your account|Back up before the switch/, 300_000)
  await page.click('button[name=skip-backup]')
  await heading(page, /Move your identity|Confirm the move/)
  const before = oldBase === SRC ? await xrpc(SRC, 'vlpds.admin.getDevMail', { auth: basic, params: { email: a.email } }).then((r) => r.token) : undefined
  const tPlc = Date.now()
  await page.click('button:has-text("Email me a confirmation code")')
  await page.locator('input[name=plc-token]').waitFor()
  const token = oldBase === SRC ? await devMailToken(SRC, a.email, before) : await mailToken(a.email, tPlc)
  await page.fill('input[name=plc-token]', token)
  await page.check('input[name=understood]')
  await page.getByRole('button', { name: /^Move my (identity|account)$/ }).click()

  // the Spaces step, after activation and before the old account goes offline
  await heading(page, /Switching over/, 120_000)
  const signInOld = page.locator('button[name=spaces-sign-in-old]')
  await signInOld.waitFor({ timeout: 60_000 })
  await shot(page, `${a.name}-spaces-sign-in-old`)
  const card = flat(await page.locator('.mig-main').innerText())
  if (!advanced) {
    const m = card.match(JARGON)
    check(!m, `${a.name}: simple mode, Spaces step: no protocol jargon`, m ? `"${m[0]}" in ${card.slice(Math.max(0, m.index - 60), m.index + 60)}` : '')
  }
  const oldHost = new URL(oldBase).host
  await signInOld.click()
  await authorize(page, a, `${a.name}-old`)
  await heading(page, /Switching over/)
  const signInNew = page.locator('button[name=spaces-sign-in-new]')
  await signInNew.waitFor({ timeout: 60_000 })
  const found = flat(await page.locator('.mig-spaces').innerText())
  check(found.includes(`Found ${a.spaces.length} spaces at ${oldHost}`), `${a.name}: lists ${a.spaces.length} spaces at the old server`, found)
  await shot(page, `${a.name}-spaces-sign-in-new`)
  let lost = false
  if (loseImport) {
    // the first import lands but its answer never arrives: the retry imports it again
    await page.route('**/xrpc/com.atproto.space.importRepo*', async (route) => {
      if (lost) return route.continue()
      lost = true
      await route.fetch()
      await route.abort('connectionreset')
    })
  }
  await signInNew.click()
  await authorize(page, a, `${a.name}-new`)
  await heading(page, /Switching over/)
  await page.locator('button[name=spaces-continue]').waitFor({ timeout: 120_000 })
  await shot(page, `${a.name}-spaces-result`)
  const result = flat(await page.locator('.mig-spaces').innerText())
  for (const s of a.spaces) {
    const label = advanced ? s : `${TYPE} (${s.split('/').pop()})`
    check(new RegExp(`${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: copied \\(\\d+ records?`).test(result), `${a.name}: ${s.split('/').pop()} shown as copied`, result)
  }
  check(/All 2 Spaces copied/.test(result), `${a.name}: the summary says all copied`, result)
  check(new RegExp(`notes\\)?: copied \\(4 records, 1 ${advanced ? 'blob' : 'file'}\\)`).test(result), `${a.name}: the space blob came too`, result)
  if (loseImport) check(lost && imports.length === a.spaces.length + 1, `${a.name}: a lost import answer was retried`, JSON.stringify(imports))
  else check(imports.length === a.spaces.length, `${a.name}: one import per space`, JSON.stringify(imports))
  check(metaImports.length === 1, `${a.name}: the space it runs (notes) moved with importSpaceMeta`, JSON.stringify(metaImports))
  await page.click('button[name=spaces-continue]')
  await heading(page, /Welcome to your new home/, 120_000)
  await shot(page, `${a.name}-done`)
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }))
  check(!/vlpds\.oauth\.(session|pending)/.test(stored), `${a.name}: no OAuth session or pending sign-in left in storage`)
  const keys = await page.evaluate(
    () =>
      new Promise((ok) => {
        const r = indexedDB.open('vlpds-oauth', 1)
        r.onsuccess = () => {
          const q = r.result.transaction('dpop-keys').objectStore('dpop-keys').count()
          q.onsuccess = () => ok(q.result)
        }
        r.onerror = () => ok(-1)
      }),
  )
  check(keys === 0, `${a.name}: the DPoP keys are deleted afterwards`, `${keys} left`)
  await page.close()
}

/** The keys the client makes are non-extractable: generate one the way the page does, try to export it. */
async function keyCheck(ctx) {
  const page = await ctx.newPage()
  await page.goto(`${VLPDS}/migrate`)
  const out = await page.evaluate(async () => {
    const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
    try {
      await crypto.subtle.exportKey('jwk', k.privateKey)
      return 'exported'
    } catch (e) {
      return `refused: ${e.name}`
    }
  })
  check(out.startsWith('refused'), 'a private key made with extractable=false cannot be exported', out)
  // a key a closed tab left behind a day ago is swept when the page loads
  const idb = (op) =>
    page.evaluate(
      (op) =>
        new Promise((ok, no) => {
          const r = indexedDB.open('vlpds-oauth', 1)
          r.onupgradeneeded = () => r.result.createObjectStore('dpop-keys')
          r.onerror = () => no(r.error)
          r.onsuccess = async () => {
            const st = () => r.result.transaction('dpop-keys', 'readwrite').objectStore('dpop-keys')
            if (op === 'plant') {
              const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
              st().put({ pair, at: Date.now() - 2 * 86400_000 }, 'stale').onsuccess = () => ok(1)
            } else st().count().onsuccess = (e) => ok(e.target.result)
          }
        }),
      op,
    )
  await idb('plant')
  await page.reload()
  await page.locator('.mig-card h1').first().waitFor()
  await sleep(500)
  check((await idb('count')) === 0, 'an orphaned DPoP key is swept on the next visit')
  await page.close()
}

// ---------------------------------------------------------------- verify

async function verify(a) {
  log(`verify: ${a.handle} on vlpds`)
  const keys = await didKeys(a.did)
  check(keys.atproto !== a.oldKeys.atproto, `${a.name}: the DID's signing key is vlpds's now`)
  check(!!keys.atproto_kem && keys.atproto_kem !== a.oldKeys.atproto_kem, `${a.name}: and so is its #atproto_kem key (the PLC op carried vlpds's recommended keys)`, JSON.stringify(keys))
  const s = await oauthLogin(VLPDS, {
    handle: a.newHandle,
    did: a.did,
    password: a.newPassword ?? a.password,
    scope: `atproto space:${TYPE}?authority=*&collection=*&action=read_self&action=create`,
  })
  for (const space of a.spaces) {
    const star = await s.xrpc('com.atproto.space.getRepo', { params: { space, repo: a.did }, raw: true })
    // an import gives the repo a new rev with the same data
    const got = await verifiedRepo(star, space, a.did)
    const want = a.before[space]
    check(got.data === want.data && JSON.stringify(got.records) === JSON.stringify(want.records), `${a.name}: ${space.split('/').pop()} has the same ${want.records.length} records and data`)
    check(got.rev > want.rev, `${a.name}: at a new rev`, `${want.rev} -> ${got.rev}`)
    // importing it again replaces it with the same records
    const again = await s.xrpc('com.atproto.space.importRepo', { bytes: star, type: 'application/octet-stream' }).then(() => null, (e) => e.message)
    const after = await verifiedRepo(await s.xrpc('com.atproto.space.getRepo', { params: { space, repo: a.did }, raw: true }), space, a.did)
    check(!again && after.data === want.data && JSON.stringify(after.records) === JSON.stringify(want.records), `${a.name}: re-importing ${space.split('/').pop()} changes nothing`, again ?? '')
  }
  const members = (await s.xrpc('com.atproto.memberspace.listMembers', { params: { space: a.spaces[1] } }).catch((e) => ({ error: e.message }))).members
  check(JSON.stringify(members) === JSON.stringify(a.members), `${a.name}: the space it runs kept its member list`, JSON.stringify(members))
  for (const [cid, hash] of Object.entries(a.blobs)) {
    const space = a.spaces[1]
    const bytes = await s.xrpc('com.atproto.space.getBlob', { params: { space, repo: a.did, cid }, raw: true }).catch((e) => Buffer.from(e.message))
    check(sha(bytes) === hash, `${a.name}: space blob ${cid.slice(0, 12)}… has the same bytes`)
  }
  // a new write on vlpds goes on from the imported repo
  const notes = a.spaces[1]
  await s.xrpc('com.atproto.space.createRecord', { body: { space: notes, repo: a.did, collection: COLL, record: { $type: COLL, text: 'after the move', createdAt: new Date().toISOString() } } })
  const star = await s.xrpc('com.atproto.space.getRepo', { params: { space: notes, repo: a.did }, raw: true })
  const after = await verifiedRepo(star, notes, a.did).catch((e) => ({ error: e.message }))
  check(after.records?.length === a.before[notes].records.length + 1 && after.rev > a.before[notes].rev, `${a.name}: a write after the move goes on from the imported repo`, JSON.stringify(after).slice(0, 200))
  const old = await xrpc(a.base, 'com.atproto.server.checkAccountStatus', {
    auth: (await xrpc(a.base, 'com.atproto.server.createSession', { body: { identifier: a.did, password: a.password } })).accessJwt,
  })
  check(old.activated === false, `${a.name}: deactivated at the old server`)
}

// ---------------------------------------------------------------- main

mkdirSync(OUT, { recursive: true })
const md = await fetch(`${VLPDS}/oauth/client-metadata.json`).then((r) => r.json())
const uiScope = /CLIENT_SCOPE =\s*'([^']+)'/.exec(readFileSync(new URL('../../ui/src/lib/oauth.ts', import.meta.url), 'utf8'))?.[1]
check(md.scope === uiScope, 'the served client metadata lists the UI client scope', `${md.scope} vs ${uiScope}`)
check(
  JSON.stringify(md.redirect_uris) === JSON.stringify([`${VLPDS}/migrate/oauth/callback`, `${VLPDS}/account/oauth/callback`]) && md.token_endpoint_auth_method === 'none' && md.dpop_bound_access_tokens === true,
  'client metadata: public, DPoP-bound, the /migrate and /account redirect URIs',
)
const { alice, erin } = await seed()
writeFileSync(`${OUT}state.json`, JSON.stringify({ alice, erin }, (k, v) => (k === 'call' ? undefined : v), 2))
const browser = await chromium.launch({ headless: !HEADED })
try {
  await keyCheck(await browser.newContext())
  for (const [a, from, opts] of [
    [alice, REF, { advanced: false, loseImport: true }],
    [erin, SRC, { advanced: true, loseImport: false }],
  ]) {
    const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 } })
    try {
      await drive(ctx, a, from, opts)
    } catch (e) {
      for (const p of ctx.pages()) await shot(p, `${a.name}-failed`).catch(() => {})
      throw e
    }
  }
} finally {
  await browser.close()
}
await verify(alice)
await verify(erin)
log(failures ? `${failures} FAILED` : 'all passed')
process.exit(failures ? 1 : 0)
