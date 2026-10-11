// The pluggable sign-in pages in a real browser (README.md): the
// authorization page's provider buttons and the Sign-In with Ethereum wallet
// page, in headless Chromium, with an injected EIP-1193 wallet that signs for
// real — secp256k1 with a recovery id over Keccak-256, the same curve and hash
// the server recovers. Fails on any page error or CSP violation.
//
//   node e2e.mjs      (VLPDS=http://localhost:2795, SHOTS=<dir for screenshots>)

import { chromium } from 'playwright'
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'

const VLPDS = process.env.VLPDS ?? 'http://localhost:2795'
// Node resolves localhost to ::1 first; the server listens on 127.0.0.1. The
// browser is given the localhost origin, since a WebAuthn/loopback client
// wants one.
const AT = VLPDS.replace('//localhost:', '//127.0.0.1:')
const SHOTS = process.env.SHOTS ?? new URL('./out/shots/', import.meta.url).pathname
const HEADED = !!process.env.HEADED
const PASSWORD = 'correct horse battery staple'
const REDIRECT = 'http://127.0.0.1/cb'
mkdirSync(SHOTS, { recursive: true })

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)
let failures = 0
function check(ok, what, detail = '') {
  if (ok) log(`  ok   ${what}`)
  else {
    failures++
    log(`  FAIL ${what} ${detail}`)
  }
}

const b64u = (b) => Buffer.from(b).toString('base64url')
const uniq = (p) => `${p}${randomBytes(3).toString('hex')}`

// ---------------------------------------------------------------- the wallet

// A fixed key, so a failure is reproducible: a real secp256k1 key whose
// address is derived the way a wallet derives it (last 20 bytes of the
// Keccak-256 of the uncompressed public key).
const PRIV = new Uint8Array(createHash('sha256').update('vlpds-e2e-wallet').digest())
const ADDRESS = '0x' + Buffer.from(keccak_256(secp256k1.getPublicKey(PRIV, false).slice(1))).subarray(12).toString('hex')

/** EIP-191 `personal_sign`, as a wallet produces it: r||s||v. */
function personalSign(message) {
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${Buffer.byteLength(message)}`, 'utf8')
  const digest = keccak_256(Buffer.concat([prefix, Buffer.from(message, 'utf8')]))
  // `prehash: false`: noble v2 hashes its input by default, and this digest is
  // already the EIP-191 one. Its recovered form is [recovery, r, s]; wallets
  // sign r||s||v.
  const rec = secp256k1.sign(digest, PRIV, { format: 'recovered', prehash: false })
  const bytes = rec.length ? rec : rec.toBytes()
  return '0x' + Buffer.concat([Buffer.from(bytes.slice(1)), Buffer.from(bytes.slice(0, 1))]).toString('hex')
}

// ------------------------------------------------------------------- clients

async function xrpc(nsid, body, auth) {
  const r = await fetch(`${AT}/xrpc/${nsid}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(auth ? { authorization: `Bearer ${auth}` } : {}) },
    body: JSON.stringify(body),
  })
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(`${nsid} ${r.status} ${JSON.stringify(j)}`)
  return j
}

/** One browser's device cookie, kept across the `/auth/*` JSON calls. */
let deviceCookie = ''
async function authPost(path, body, bearer) {
  const r = await fetch(`${AT}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(deviceCookie ? { cookie: deviceCookie } : {}),
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
    },
    body: JSON.stringify(body),
  })
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const v = c.split(';')[0]
    if (v.startsWith('vlpds-device=')) deviceCookie = v
  }
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(`${path} ${r.status} ${JSON.stringify(j)}`)
  return j
}

/** A DPoP key for a loopback OAuth client, as the account pages use. */
class DpopKey {
  constructor() {
    this.key = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const { kty, crv, x, y } = this.key.publicKey.export({ format: 'jwk' })
    this.jwk = { kty, crv, x, y }
  }
  proof(htm, htu, ath) {
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: this.jwk }
    const payload = {
      jti: b64u(randomBytes(12)),
      htm,
      htu,
      iat: Math.floor(Date.now() / 1000),
      ...(this.nonce ? { nonce: this.nonce } : {}),
      ...(ath ? { ath } : {}),
    }
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`
    const sig = sign('sha256', Buffer.from(input), { key: this.key.privateKey, dsaEncoding: 'ieee-p1363' })
    return `${input}.${b64u(sig)}`
  }
  absorb(res) {
    const n = res.headers.get('dpop-nonce')
    if (n) this.nonce = n
  }
}

async function asPost(key, path, form) {
  const htu = `${VLPDS}${path}`
  for (let i = 0; i < 3; i++) {
    const r = await fetch(AT + path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: key.proof('POST', htu) },
      body: new URLSearchParams(form),
    })
    key.absorb(r)
    const j = await r.json().catch(() => ({}))
    if (j.error === 'use_dpop_nonce') continue
    return { status: r.status, body: j }
  }
  throw new Error(`${path}: no DPoP nonce accepted`)
}

/** A DPoP-bound read, as an OAuth client makes it. */
async function dpopGet(key, path, access) {
  const htu = `${VLPDS}${path}`
  for (let i = 0; i < 3; i++) {
    const r = await fetch(AT + path, {
      headers: { authorization: `DPoP ${access}`, dpop: key.proof('GET', htu, b64u(createHash('sha256').update(access).digest())) },
    })
    key.absorb(r)
    if (r.status === 401 && /use_dpop_nonce/.test(r.headers.get('www-authenticate') ?? '')) continue
    return { status: r.status, body: await r.json().catch(() => ({})) }
  }
  throw new Error(`${path}: no DPoP nonce accepted`)
}

// ---------------------------------------------------------------------- run

const handle = uniq('wallet')
const email = `${handle}@example.com`
const acct = await xrpc('com.atproto.server.createAccount', { handle: `${handle}.vlpds.test`, password: PASSWORD, email })
log(`account ${acct.handle} ${acct.did}`)

// Link the wallet over the API: the browser part under test is the sign-in.
const link = await authPost('/auth/link', { provider: 'siwe', address: ADDRESS, password: PASSWORD }, acct.accessJwt)
if (link.challenge?.kind !== 'siwe') throw new Error(`expected a wallet challenge: ${JSON.stringify(link)}`)
const linked = await authPost('/auth/continue', {
  txn: link.txnId,
  step: 'link',
  message: link.challenge.message,
  signature: personalSign(link.challenge.message),
})
check(linked.status === 'linked', 'the wallet is linked to the account', JSON.stringify(linked))

// An OAuth client's pushed request, so the authorization page has something to
// authorize (a loopback client, as the reference's own pages use).
const key = new DpopKey()
const scope = 'atproto transition:generic'
const clientId = `http://localhost?scope=${encodeURIComponent(scope)}&redirect_uri=${encodeURIComponent(REDIRECT)}`
const verifier = b64u(randomBytes(32))
const par = await asPost(key, '/oauth/par', {
  client_id: clientId,
  response_type: 'code',
  redirect_uri: REDIRECT,
  scope,
  state: b64u(randomBytes(8)),
  code_challenge: b64u(createHash('sha256').update(verifier).digest()),
  code_challenge_method: 'S256',
})
if (par.status !== 201) throw new Error(`PAR ${par.status} ${JSON.stringify(par.body)}`)
const authorizeUrl = `${VLPDS}/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(par.body.request_uri)}`

const browser = await chromium.launch({ headless: !HEADED })
try {
  const ctx = await browser.newContext()
  const page = await ctx.newPage()
  const errors = []
  const msgs = []
  const net = []
  page.on('pageerror', (e) => errors.push(String(e)))
  page.on('console', (m) => {
    msgs.push(`${m.type()}: ${m.text()}`)
    if (m.type() === 'error') errors.push(m.text())
  })
  // The wallet page's own calls, so a failure says which step stopped it.
  page.on('response', (r) => {
    if (r.url().includes('/auth/')) {
      const loc = r.headers()['location']
      net.push(`${r.status()} ${new URL(r.url()).pathname}${loc ? ` -> ${loc.slice(0, 80)}` : ''}`)
    }
  })
  page.on('request', (r) => {
    if (r.method() === 'POST' && r.url().includes('/auth/')) {
      net.push(`POST ${new URL(r.url()).pathname} ${(r.postData() ?? '').slice(0, 240)}`)
    }
  })
  const shot = (n) => page.screenshot({ path: `${SHOTS}${n}.png`, fullPage: true })
  // The wallet: a page script can't sign, so the page asks this process, which
  // holds the key.
  await page.exposeFunction('__vlpdsSign', (message) => personalSign(message))
  await page.addInitScript(
    ({ address }) => {
      window.ethereum = {
        request: async ({ method, params }) => {
          if (method === 'eth_requestAccounts') return [address]
          if (method === 'personal_sign') return await window.__vlpdsSign(params[0])
          throw new Error(`the test wallet does not implement ${method}`)
        },
      }
    },
    { address: ADDRESS },
  )

  log('authorization page')
  await page.goto(authorizeUrl)
  await page.waitForSelector('text=Continue with Ethereum', { timeout: 15000 })
  check(true, 'the sign-in page offers the configured method')
  check((await page.locator('form input[name=provider]').count()) === 0, 'a wallet needs no form post')
  await shot('01-signin')

  log('wallet page')
  await page.click('text=Continue with Ethereum')
  await page.waitForSelector('#vlpds-wallet', { timeout: 15000 })
  // The page runs only its own script, by hash; a CSP violation would show up
  // in the console as an error.
  check((await page.locator('#vlpds-wallet').count()) === 1, 'the wallet page renders its button')
  await shot('02-wallet')

  log('sign')
  try {
    await page.click('#vlpds-wallet')
    await page.waitForSelector('text=Authorize access', { timeout: 20000 })
  } catch (e) {
    await shot('99-stuck')
    throw new Error(
      `${e.message}\n  at ${page.url()}\n  auth traffic: ${net.join(' | ') || 'none'}\n  console: ${msgs.join(' | ') || 'none'}`,
    )
  }
  check(true, 'the signature was accepted and the consent page shown')
  await shot('03-consent')
  check(
    (await page.content()).includes(handle),
    'the consent page names the account the wallet signed in as',
  )

  log('allow')
  await ctx.route('http://127.0.0.1/cb*', (route) => route.abort())
  const cb = page.waitForRequest((r) => r.url().startsWith(REDIRECT), { timeout: 20000 })
  await page.locator('button[value=allow]').click()
  const code = new URL((await cb).url().replace('#', '?')).searchParams.get('code')
  check(!!code, 'the consent redirect carried an authorization code')

  const tok = await asPost(key, '/oauth/token', {
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  })
  check(tok.status === 200 && !!tok.body.access_token, 'the code exchanged for tokens', JSON.stringify(tok.body))
  const me = await dpopGet(key, '/xrpc/com.atproto.server.getSession', tok.body.access_token)
  check(me.body.did === acct.did, 'the token is the account the wallet signed in as', JSON.stringify(me.body))

  check(errors.length === 0, 'no page errors and no CSP violations', errors.join(' | '))
  await shot('04-done')
} finally {
  await browser.close()
}

log(failures === 0 ? 'all checks passed' : `${failures} check(s) failed`)
process.exit(failures === 0 ? 0 : 1)