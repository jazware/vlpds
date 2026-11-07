// The account page's "Your spaces" section in headless Chromium (README.md),
// against a local in-memory vlpds with --spaces and a second one without it.
// Connect (OAuth consent), both lists, the record browser, the owner grant
// on top of the first, add and remove a member by handle, delete a space,
// and the tokens revoked (with no keys or sessions left) on Disconnect, on
// leaving the section and on signing out. Fails on any page error or CSP
// violation in the console.
//
//   node e2e.mjs      (run.sh starts the servers; SHOTS=<dir> for the screenshots)

import { chromium } from 'playwright'
import { randomBytes } from 'node:crypto'
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { hostUrl, oauthLogin } from '../migrate/lib/oauth.mjs'

const VLPDS = process.env.VLPDS ?? 'http://127.0.0.1:2793'
const OFF = process.env.VLPDS_OFF ?? 'http://127.0.0.1:2794'
const SHOTS = process.env.SHOTS ?? new URL('./out/shots/', import.meta.url).pathname
const HEADED = !!process.env.HEADED
const TYPE = 'com.example.group'
const COLL = 'com.example.post'

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

async function xrpc(base, nsid, { params, body, auth } = {}) {
  const q = params ? `?${new URLSearchParams(params)}` : ''
  const r = await fetch(hostUrl(`${base}/xrpc/${nsid}${q}`), {
    method: body !== undefined ? 'POST' : 'GET',
    headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(auth ? { authorization: `Bearer ${auth}` } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw Object.assign(new Error(`${nsid} ${r.status} ${JSON.stringify(j)}`), { error: j.error, status: r.status })
  return j
}

// ---------------------------------------------------------------- seed

const RUN = randomBytes(2).toString('hex')
const MEMBERS = { $type: 'com.atproto.memberspace.policy' }
const SEED_SCOPE = `atproto space:${TYPE}?authority=*&collection=*&action=read&action=create&manage=create&manage=update`

async function account(base, name, { oauth = true } = {}) {
  const handle = `${name}${RUN}.vlpds.test`
  const password = randomBytes(12).toString('base64url')
  const r = await xrpc(base, 'com.atproto.server.createAccount', { body: { handle, password, email: `${name}${RUN}@example.com` } })
  const a = { name, handle, password, did: r.did, jwt: r.accessJwt }
  if (oauth) {
    const s = await oauthLogin(base, { handle, did: a.did, password, scope: SEED_SCOPE })
    a.call = (nsid, o = {}) => s.xrpc(nsid, o)
  }
  return a
}

const createSpace = async (a, skey) =>
  (await a.call('com.atproto.space.createSpace', { body: { spaceType: TYPE, skey, policy: MEMBERS } })).uri

async function write(a, space, n) {
  for (let i = 0; i < n; i++) {
    const record = { $type: COLL, text: `${a.name}'s note ${i + 1} in ${space.split('/').pop()}`, createdAt: new Date().toISOString() }
    await a.call('com.atproto.space.createRecord', { body: { space, repo: a.did, collection: COLL, record } })
  }
}

async function seed() {
  log('seed')
  const alice = await account(VLPDS, 'alice')
  const bob = await account(VLPDS, 'bob')
  const carol = await account(VLPDS, 'carol', { oauth: false })
  const club = await createSpace(alice, 'bookclub')
  const garden = await createSpace(alice, 'garden')
  await alice.call('com.atproto.memberspace.putMember', { body: { space: club, did: bob.did, read: true, write: true } })
  await write(alice, club, 3)
  await write(bob, club, 2)
  const notes = await createSpace(bob, 'notes')
  await bob.call('com.atproto.memberspace.putMember', { body: { space: notes, did: alice.did, read: true, write: true } })
  await write(alice, notes, 2)
  log(`  alice runs bookclub (bob writes there) and garden, writes in bob's notes`)
  return { alice, bob, carol, club, garden, notes }
}

// ---------------------------------------------------------------- browser helpers

const flat = (s) => s.replace(/\s+/g, ' ').trim()

function watch(page, label) {
  page.on('pageerror', (e) => check(false, `${label}: no page error`, e.message))
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const t = m.text()
    // a refused request logs a resource error; only CSP and script errors count
    if (/Failed to load resource/.test(t)) return
    check(false, `${label}: no console error`, t)
  })
}

async function signIn(page, a, base = VLPDS) {
  await page.goto(`${base}/account`)
  await page.getByLabel('Handle, DID or email').fill(a.handle)
  await page.getByLabel('Password').fill(a.password)
  await page.locator('form button[type=submit]').click()
  await page.locator('.sidenav nav').waitFor()
}

/** On this vlpds's authorization pages: the account, the password if asked, then Allow. */
async function authorize(page, a, shot) {
  await page.waitForURL((u) => u.pathname.startsWith('/oauth/authorize'), { timeout: 30_000 })
  for (let i = 0; i < 4; i++) {
    if (await page.locator('button[value=allow]').count()) break
    const pick = page.locator(`form:has(input[name=did][value="${a.did}"]) button`)
    if (await pick.count()) {
      await pick.click()
      continue
    }
    if (await page.locator('input#password').count()) {
      const id = page.locator('input#identifier')
      if ((await id.count()) && !(await id.inputValue())) await id.fill(a.handle)
      await page.fill('input#password', a.password)
      await page.click('button[value=sign-in]')
      continue
    }
    await sleep(200)
  }
  await page.locator('button[value=allow]').waitFor({ timeout: 30_000 })
  const consent = flat(await page.locator('body').innerText())
  if (shot) await shot('consent')
  await page.click('button[value=allow]')
  await page.waitForURL((u) => u.pathname.startsWith('/account/spaces'), { timeout: 30_000 })
  return consent
}

async function connect(page, a, shot) {
  await page.locator('button[name=spaces-connect]').click()
  const consent = await authorize(page, a, shot)
  await page.locator('#spaces-written').waitFor({ timeout: 30_000 })
  return consent
}

const oauthStorage = (page) => page.evaluate(() => Object.keys(sessionStorage).filter((k) => k.startsWith('vlpds.oauth.')))

const idbCount = (page) =>
  page.evaluate(
    () =>
      new Promise((ok) => {
        const r = indexedDB.open('vlpds-oauth', 1)
        r.onupgradeneeded = () => r.result.createObjectStore('dpop-keys')
        r.onsuccess = () => {
          const q = r.result.transaction('dpop-keys').objectStore('dpop-keys').count()
          q.onsuccess = () => ok(q.result)
        }
        r.onerror = () => ok(-1)
      }),
  )

/** The account page's OAuth sessions at the server (the seed's own client is another). */
async function pageSessions(a) {
  const r = await xrpc(VLPDS, 'vlpds.oauth.listSessions', { auth: a.jwt })
  return (r.sessions ?? []).filter((s) => String(s.clientId).includes(encodeURIComponent('/account/oauth/callback')) || String(s.clientId).includes('/oauth/client-metadata.json'))
}

/** Gone from this tab and from the server: no session, no pending sign-in, no key, no server session. */
async function nothingLeft(page, a, what) {
  let keys = []
  let n = -1
  for (let i = 0; i < 25; i++) {
    keys = await oauthStorage(page)
    n = await idbCount(page)
    if (!keys.length && n === 0) break
    await sleep(200)
  }
  check(keys.length === 0, `${what}: no OAuth session or pending sign-in left in sessionStorage`, JSON.stringify(keys))
  check(n === 0, `${what}: the DPoP key is deleted`, `${n} left`)
  const left = await pageSessions(a)
  check(left.length === 0, `${what}: no account-page session left at the server`, JSON.stringify(left))
}

/** Keeps the live token and its key (the CryptoKey object, still usable after the stored copy is deleted). */
const holdToken = (page) =>
  page.evaluate(
    () =>
      new Promise((ok, no) => {
        const st = JSON.parse(sessionStorage.getItem('vlpds.oauth.session.spaces'))
        const r = indexedDB.open('vlpds-oauth', 1)
        r.onerror = () => no(r.error)
        r.onsuccess = () => {
          const q = r.result.transaction('dpop-keys').objectStore('dpop-keys').get(st.keyId)
          q.onsuccess = () => {
            window.__held = { access: st.access, pair: q.result.pair, did: st.did }
            ok(true)
          }
        }
      }),
  )

/** listSpaces with the held token, DPoP-signed with the held key: the status. */
const useHeld = (page) =>
  page.evaluate(async () => {
    const { access, pair } = window.__held
    const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const enc = new TextEncoder()
    const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey)
    const url = `${location.origin}/xrpc/com.atproto.space.listSpaces`
    let nonce
    for (let i = 0; i < 2; i++) {
      const payload = {
        jti: crypto.randomUUID(),
        htm: 'GET',
        htu: url,
        iat: Math.floor(Date.now() / 1000),
        ath: b64u(await crypto.subtle.digest('SHA-256', enc.encode(access))),
        ...(nonce ? { nonce } : {}),
      }
      const input = `${b64u(enc.encode(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty, crv, x, y } })))}.${b64u(enc.encode(JSON.stringify(payload)))}`
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, enc.encode(input))
      const r = await fetch(url, { headers: { Authorization: `DPoP ${access}`, DPoP: `${input}.${b64u(sig)}` } })
      nonce = r.headers.get('dpop-nonce') ?? nonce
      const www = r.headers.get('www-authenticate') ?? ''
      if (r.status === 401 && /use_dpop_nonce/.test(www) && i === 0) continue
      return { status: r.status, www }
    }
  })

// ---------------------------------------------------------------- the flow

async function flow(browser, w) {
  const { alice, carol, club, garden } = w
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } })
  const page = await ctx.newPage()
  watch(page, 'flow')
  await signIn(page, alice)
  const nav = page.locator('.sidenav nav a', { hasText: /^Spaces$/ })
  await nav.waitFor()
  check(true, 'the Spaces link is in the account nav')
  await nav.click()
  await page.locator('button[name=spaces-connect]').waitFor()
  check((await oauthStorage(page)).length === 0, 'before Connect: no OAuth session in the tab')

  log('connect')
  const consent = await connect(page, alice)
  check(/read your own space repos/i.test(consent), 'the consent asks to read your own space repos', consent.slice(0, 400))
  check(!/change and delete|delete spaces/i.test(consent), 'the first consent asks to manage nothing')
  check(page.url() === `${VLPDS}/account/spaces`, 'back on /account/spaces, no code in the address bar', page.url())

  log('lists')
  const written = flat(await page.locator('#spaces-written').innerText())
  const governed = flat(await page.locator('#spaces-governed').innerText())
  check(/2 spaces/.test(written) && /bookclub/.test(written) && /notes/.test(written), 'spaces you write in: bookclub and notes', written)
  check(new RegExp(`@${w.bob.handle.replace(/\./g, '\\.')}`).test(written), "bob's space shows his verified handle", written)
  check(/bookclub you 3/.test(written) || /bookclub\s.*\b3\b/.test(written), 'bookclub: 3 of your records', written)
  check(/notes .*\b2\b/.test(written), 'notes: 2 of your records', written)
  check(!/garden/.test(written), "garden isn't listed as written in (nothing of yours there)", written)
  check(/2 spaces/.test(governed) && /bookclub 1 1 members · members/.test(governed) && /garden 0 0 members · members/.test(governed), 'spaces you run: members, writers, policy', governed)

  log('browse')
  await page.locator('#spaces-written a', { hasText: 'bookclub' }).click()
  await page.locator('#space-records tbody tr').first().waitFor()
  const rows = await page.locator('#space-records tbody tr').count()
  check(rows === 3, 'bookclub: your 3 records, not bob’s', `${rows} rows`)
  await page.locator('#space-records tbody tr').first().click()
  const opened = flat(await page.locator('#space-records .record-open').innerText())
  check(/alice's note \d in bookclub/.test(opened) && /com\.example\.post/.test(opened), 'a record opens to its value', opened)
  const members = flat(await page.locator('#space-members').innerText())
  check(members.includes(`@${w.bob.handle}`) && /read and write/.test(members), 'members: bob, read and write', members)
  check((await page.locator('button[name=spaces-remove]').count()) === 0, 'no owner controls before Manage')

  log('owner grant')
  await page.click('button[name=spaces-manage]')
  await page.locator('button[name=spaces-allow-manage]').waitFor()
  await page.click('button[name=spaces-allow-manage]')
  const consent2 = await authorize(page, alice)
  check(/manage your spaces/i.test(consent2) && !/manage in every space/i.test(consent2), 'the second consent asks to manage your spaces (not every space)', consent2.slice(0, 500))
  await page.locator('#space-add').waitFor({ timeout: 30_000 })
  check(new URL(page.url()).pathname.endsWith('/bookclub') && /manage=1/.test(page.url()), 'back on the space with the controls open', page.url())
  const scope = await page.evaluate(() => JSON.parse(sessionStorage.getItem('vlpds.oauth.session.spaces')).scope)
  check(scope.includes(`space:*?authority=${alice.did}&action=read_self&manage=update&manage=delete`) && scope.includes('space:*?authority=*&action=read_self'), 'the token carries both grants, the owner one for this account only', scope)
  check((await pageSessions(alice)).length === 1, 'the first grant was revoked when the second replaced it', JSON.stringify(await pageSessions(alice)))
  check((await idbCount(page)) === 1, 'one DPoP key left (the first grant’s is deleted)')

  log('add and remove a member')
  await page.fill('input[name=member-handle]', `@${carol.handle}`)
  await page.selectOption('select[name=member-access]', 'read')
  await page.click('button[name=spaces-add]')
  const dialog = page.locator('dialog.modal[open]')
  await dialog.waitFor()
  check(flat(await dialog.innerText()).includes(`@${carol.handle}`), 'the add confirmation names carol')
  await dialog.locator('button[type=submit]').click()
  await page.locator('#space-add .notice.ok').waitFor()
  const api = async () => (await alice.call('com.atproto.memberspace.listMembers', { params: { space: club } })).members
  const afterAdd = await api()
  check(afterAdd.some((m) => m.did === carol.did && m.read && !m.write), 'the API lists carol as a reader', JSON.stringify(afterAdd))
  await page.locator('#space-members', { hasText: carol.handle }).waitFor()
  const row = page.locator('#space-members tr', { hasText: carol.handle })
  await row.locator('button[name=spaces-remove]').click()
  await page.locator('dialog.modal[open]').waitFor()
  await page.locator('dialog.modal[open] button[type=submit]').click()
  await page.locator('dialog.modal[open]').waitFor({ state: 'detached', timeout: 10_000 }).catch(() => {})
  for (let i = 0; i < 25 && (await api()).some((m) => m.did === carol.did); i++) await sleep(200)
  const afterRm = await api()
  check(!afterRm.some((m) => m.did === carol.did) && afterRm.some((m) => m.did === w.bob.did), 'the API no longer lists carol (bob stays)', JSON.stringify(afterRm))

  log('delete a space')
  await page.goto(`${VLPDS}/account/spaces/${encodeURIComponent(alice.did)}/${TYPE}/garden?manage=1`)
  await page.locator('button[name=spaces-delete]').waitFor()
  await page.click('button[name=spaces-delete]')
  const del = page.locator('dialog.modal[open]')
  await del.waitFor()
  const go = del.locator('button[type=submit]')
  check(await go.isDisabled(), 'delete stays disabled until the space key is typed')
  await del.locator('input[type=text]').fill('garden')
  check(!(await go.isDisabled()), 'typing the key enables it')
  await go.click()
  await page.waitForURL(`${VLPDS}/account/spaces`)
  const gone = await alice.call('com.atproto.space.getSpace', { params: { space: garden } }).catch((e) => e)
  check(/SpaceNotFound|SpaceDeleted/.test(String(gone?.message)), 'the API says garden is gone', String(gone?.message ?? JSON.stringify(gone)))
  await page.locator('#spaces-governed').waitFor()
  check(!/garden/.test(await page.locator('#spaces-governed').innerText()), 'garden is off the list')

  log('disconnect revokes')
  await holdToken(page)
  const live = await useHeld(page)
  check(live.status === 200, 'the live token works (DPoP-signed in the page)', JSON.stringify(live))
  await page.click('button[name=spaces-disconnect]')
  await page.locator('button[name=spaces-connect]').waitFor()
  const dead = await useHeld(page)
  check(dead.status === 401 && /invalid_token/.test(dead.www), 'after Disconnect the same token is refused', JSON.stringify(dead))
  await nothingLeft(page, alice, 'Disconnect')

  log('leaving the section revokes')
  await connect(page, alice)
  check((await pageSessions(alice)).length === 1, 'connected again')
  await page.locator('.sidenav nav a', { hasText: /^Repository$/ }).click()
  await nothingLeft(page, alice, 'leaving the section')

  log('signing out revokes')
  await page.locator('.sidenav nav a', { hasText: /^Spaces$/ }).click()
  await connect(page, alice)
  await holdToken(page)
  await page.locator('.topbar button', { hasText: 'Sign out' }).click()
  await page.getByLabel('Password').waitFor()
  const dead2 = await useHeld(page)
  check(dead2.status === 401, 'after Sign out the token is refused', JSON.stringify(dead2))
  await nothingLeft(page, alice, 'Sign out')
  await ctx.close()
}

async function withoutSpaces(browser) {
  log('a server without Spaces')
  const a = await account(OFF, 'dave', { oauth: false })
  const ctx = await browser.newContext()
  const page = await ctx.newPage()
  watch(page, 'off')
  await signIn(page, a, OFF)
  await sleep(500)
  const nav = flat(await page.locator('.sidenav nav').innerText())
  check(!/\bSpaces\b/.test(nav), 'no Spaces link without --spaces', nav)
  await page.goto(`${OFF}/account/spaces`)
  await page.locator('.notice', { hasText: "doesn't run Spaces" }).waitFor()
  check((await page.locator('button[name=spaces-connect]').count()) === 0, 'and no Connect button at /account/spaces')
  await ctx.close()
}

// ---------------------------------------------------------------- screenshots

const SIZES = [
  { name: 'phone', viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 },
  { name: 'desktop', viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1 },
]
const SCENES = []

async function gallery(browser, w) {
  rmSync(SHOTS, { recursive: true, force: true })
  mkdirSync(SHOTS, { recursive: true })
  const { alice, club } = w
  const clubPath = `/account/spaces/${encodeURIComponent(alice.did)}/${TYPE}/bookclub`
  for (const size of SIZES)
    for (const scheme of ['light', 'dark']) {
      const tag = `${size.name}-${scheme}`
      log(`screenshots: ${tag}`)
      const ctx = await browser.newContext({ viewport: size.viewport, deviceScaleFactor: size.deviceScaleFactor, colorScheme: scheme })
      const page = await ctx.newPage()
      watch(page, tag)
      const shot = async (scene) => {
        if (!SCENES.includes(scene)) SCENES.push(scene)
        // a modal is about the viewport; a full-page capture smears the sticky top bar over it
        const modal = (await page.locator('dialog.modal[open]').count()) > 0
        await page.screenshot({ path: `${SHOTS}${scene}-${tag}.png`, fullPage: !modal })
      }
      await signIn(page, alice)
      await page.goto(`${VLPDS}/account/spaces`)
      await page.locator('button[name=spaces-connect]').waitFor()
      await shot('01-connect')
      await connect(page, alice, (s) => shot(`02-${s}`))
      await sleep(300)
      await shot('03-overview')
      await page.goto(`${VLPDS}${clubPath}`)
      await page.locator('#space-records tbody tr').first().click()
      await page.locator('#space-records .record-open').waitFor()
      await shot('04-space')
      await page.click('button[name=spaces-manage]')
      await page.locator('button[name=spaces-allow-manage]').waitFor()
      await shot('05-owner-grant')
      await page.click('button[name=spaces-allow-manage]')
      await authorize(page, alice, (s) => shot(`06-owner-${s}`))
      await page.locator('#space-add').waitFor()
      await sleep(300)
      await shot('07-owner-controls')
      await page.fill('input[name=member-handle]', w.carol.handle)
      await page.click('button[name=spaces-add]')
      await page.locator('dialog.modal[open]').waitFor()
      await shot('08-add-confirm')
      await page.locator('dialog.modal[open] button', { hasText: 'Cancel' }).click()
      await page.click('button[name=spaces-delete]')
      await page.locator('dialog.modal[open]').waitFor()
      await shot('09-delete-confirm')
      await page.locator('dialog.modal[open] button', { hasText: 'Cancel' }).click()
      await page.click('button[name=spaces-disconnect]')
      await page.locator('button[name=spaces-connect]').waitFor()
      await ctx.close()
    }
  void club
  const imgs = readdirSync(SHOTS).filter((f) => f.endsWith('.png'))
  const cells = SCENES.map(
    (s) =>
      `<section><h2>${s.slice(3)}</h2><div class="row">${['phone-light', 'phone-dark', 'desktop-light', 'desktop-dark']
        .filter((t) => imgs.includes(`${s}-${t}.png`))
        .map((t) => `<figure class="${t.split('-')[0]}"><a href="${s}-${t}.png"><img src="${s}-${t}.png" loading="lazy"></a><figcaption>${t}</figcaption></figure>`)
        .join('')}</div></section>`,
  )
  writeFileSync(
    `${SHOTS}index.html`,
    `<!doctype html><meta charset="utf-8"><title>Your spaces: screenshots</title>
<style>body{font:14px system-ui;margin:24px;background:#f4f4f2;color:#222}h2{font-size:16px;margin:28px 0 8px}.row{display:flex;gap:16px;align-items:flex-start;overflow-x:auto}figure{margin:0}figure.phone img{width:220px}figure.desktop img{width:520px}img{border:1px solid #ccc;display:block}figcaption{color:#666;font-size:12px;margin-top:4px}</style>
<h1>Account page: Your spaces</h1><p>Phone (390 px) and desktop (1280 px), light and dark.</p>${cells.join('\n')}`,
  )
  log(`  ${imgs.length} screenshots and index.html in ${SHOTS}`)
}

// ---------------------------------------------------------------- main

const md = await fetch(hostUrl(`${VLPDS}/oauth/client-metadata.json`)).then((r) => r.json())
check(md.redirect_uris?.includes(`${VLPDS}/account/oauth/callback`), 'the client metadata lists /account/oauth/callback', JSON.stringify(md.redirect_uris))
const w = await seed()
const browser = await chromium.launch({ headless: !HEADED })
try {
  await gallery(browser, w)
  await flow(browser, w)
  await withoutSpaces(browser)
} finally {
  await browser.close()
}
log(failures ? `${failures} FAILED` : 'all ok')
process.exit(failures ? 1 : 0)
