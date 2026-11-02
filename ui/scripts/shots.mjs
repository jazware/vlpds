// Screenshots of the sign-in providers console page and the account page's Sign-in methods
// section against the mock (dev/mock.mjs): `npm run shots [outDir]` (default shots/, gitignored).
// Starts two dev servers (feature level 2, and level 1 for the not-available state), shoots
// desktop and phone, and exits 1 on page errors or console errors.

import { chromium } from 'playwright'
import { spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { resolve } from 'node:path'

const out = resolve(process.argv[2] ?? 'shots')
mkdirSync(out, { recursive: true })
const UI = new URL('..', import.meta.url).pathname

function serve(port, extra = {}) {
  const p = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--port', String(port), '--strictPort'], { cwd: UI, env: { ...process.env, VLPDS_MOCK: '1', ...extra }, stdio: ['ignore', 'pipe', 'inherit'] })
  p.stdout.resume()
  return new Promise((ok, no) => {
    p.on('exit', (c) => no(new Error(`vite exited ${c}`)))
    const tick = () => fetch(`http://localhost:${port}/`).then(() => ok(p), () => setTimeout(tick, 200))
    tick()
  })
}

const servers = [await serve(5731), await serve(5732, { VLPDS_MOCK_LEVEL: '1' })]
const browser = await chromium.launch()
const stop = () => servers.forEach((s) => s.kill())
process.on('exit', stop)
process.on('uncaughtException', (e) => (console.error(e), process.exit(1)))
let failures = 0
const session = { did: 'did:plc:mock', handle: 'alice.example.com', accessJwt: 'mock', refreshJwt: 'mock' }

async function page(base, { w, theme, account }) {
  const ctx = await browser.newContext({ viewport: { width: w, height: 900 }, colorScheme: theme })
  await ctx.addInitScript(([s, acct]) => {
    if (acct) sessionStorage.setItem('vlpds.session', JSON.stringify(s))
  }, [session, account])
  const pg = await ctx.newPage()
  pg.on('pageerror', (e) => (failures++, console.error('pageerror', e.message)))
  pg.on('console', (m) => {
    if (m.type() === 'error' && !/status of 404|status of 501|status of 40[01]/.test(m.text())) (failures++, console.error('console', m.text()))
  })
  return pg
}
const shot = async (pg, name, sel) => {
  const f = `${out}/${name}.png`
  if (sel) await pg.locator(sel).first().screenshot({ path: f })
  else await pg.screenshot({ path: f })
  console.log(f)
}

for (const [w, theme, tag] of [[1440, 'light', 'desktop-light'], [1440, 'dark', 'desktop-dark'], [400, 'light', 'phone']]) {
  const pg = await page('http://localhost:5731', { w, theme })
  await pg.goto('http://localhost:5731/admin/signin')
  await pg.getByText('Example Corp').first().waitFor()
  await shot(pg, `providers-${tag}`)
  if (tag === 'desktop-light') {
    await pg.getByText('Apple').first().click()
    await pg.getByText('Credentials').first().waitFor()
    await pg.waitForTimeout(600)
    await shot(pg, 'provider-drawer')
    await pg.keyboard.press('Escape')
    await pg.getByRole('button', { name: 'Add provider…' }).click()
    await pg.getByLabel('Name', { exact: true }).waitFor()
    await shot(pg, 'form-add', '.cx-dlg')
    await pg.getByLabel('Name', { exact: true }).fill('Unreachable')
    await pg.getByLabel('ID', { exact: true }).fill('unreachable')
    await pg.getByLabel('Issuer', { exact: true }).fill('https://unreachable.example.com')
    await pg.getByLabel('Client ID').fill('abc')
    await pg.getByLabel('Client secret', { exact: true }).fill('s3cret')
    await pg.locator('.cx-dlg').getByRole('button', { name: 'Add provider', exact: true }).click()
    await pg.getByRole('button', { name: 'Save without checking issuer' }).waitFor()
    await pg.locator('.cxs-err').scrollIntoViewIfNeeded()
    await shot(pg, 'form-unreachable', '.cx-dlg')
    await pg.getByRole('button', { name: 'Save without checking issuer' }).click()
    await pg.getByText('node-c').waitFor()
    await shot(pg, 'results', '.cx-dlg')
    await pg.getByRole('button', { name: 'Done' }).click()
    await pg.getByText('Unreachable').first().click()
    await pg.getByRole('button', { name: 'Edit…' }).click()
    await pg.getByText('stored', { exact: true }).waitFor()
    await shot(pg, 'form-edit', '.cx-dlg')
    await pg.keyboard.press('Escape')
    await pg.getByRole('button', { name: 'Remove…' }).click()
    await shot(pg, 'remove', '.cx-dlg')
  }
  await pg.context().close()
}

{
  const pg = await page('', { w: 1440, theme: 'light' })
  await pg.goto('http://localhost:5732/admin/signin')
  await pg.getByText('Not available').waitFor()
  await shot(pg, 'providers-unavailable')
  await pg.context().close()
}

for (const [w, theme, tag] of [[1440, 'light', 'desktop'], [1440, 'dark', 'dark'], [400, 'light', 'phone']]) {
  const pg = await page('', { w, theme, account: true })
  await pg.goto('http://localhost:5731/account/security')
  await pg.locator('#sign-in-methods').waitFor()
  await pg.getByText('alice@old.example.org').waitFor()
  await shot(pg, `account-${tag}`, '#sign-in-methods')
  const manage = await pg.locator('#sign-in-methods').getByRole('link', { name: 'Manage' }).getAttribute('href')
  if (manage !== '/oauth/account?login_hint=did%3Aplc%3Amock&return=sign-in-methods#sign-in-methods') (failures++, console.error('bad Manage link', manage))
  await pg.context().close()
}
{
  // signed out: the provider buttons, then a returned sign-in picks its session up
  const pg = await page('', { w: 1440, theme: 'light' })
  await pg.goto('http://localhost:5731/account')
  await pg.getByRole('link', { name: 'Continue with Google' }).waitFor()
  await shot(pg, 'account-signin-providers', '.card')
  const href = await pg.getByRole('link', { name: 'Continue with Apple' }).getAttribute('href')
  if (href !== '/oauth/federated/start?provider=apple&account=1&app=1') (failures++, console.error('bad link', href))
  await pg.goto('http://localhost:5731/account?signin=device')
  await pg.getByText('@alice.example.com').first().waitFor()
  if (pg.url().includes('signin=')) (failures++, console.error('query param kept'))
  await pg.context().close()
  const pg2 = await page('', { w: 1440, theme: 'light' })
  await pg2.goto('http://localhost:5731/account?signin=device')
  await pg2.getByText('expired or was already used').waitFor()
  await shot(pg2, 'account-signin-expired', '.card')
  await pg2.context().close()
}
{
  const pg = await page('', { w: 1440, theme: 'light', account: true })
  await pg.goto('http://localhost:5732/account/security')
  await pg.getByText('Two-factor sign-in').first().waitFor()
  await pg.waitForTimeout(500)
  const n = await pg.locator('#sign-in-methods').count()
  console.log(n === 0 ? 'ok: section hidden when unavailable and empty' : 'FAIL: section shown')
  if (n) failures++
  await pg.context().close()
}

await browser.close()
process.exit(failures ? 1 : 0)
