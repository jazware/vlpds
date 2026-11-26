// Screenshots of the sign-in providers console page and the account page's Sign-in methods
// and Connected apps sections against the mock (dev/mock.mjs): `npm run shots [outDir]` (default shots/, gitignored).
// Starts two dev servers (feature level 2, and level 1 for the not-available state), shoots
// desktop and phone, and exits 1 on page errors or console errors.
// VLPDS_SHOTS_BRAND=<dir> adds a branded run (outDir/brand/): the landing and account pages with the
// made-up brand `VLPDS_BRAND_DUMP=<dir> cargo test --lib brand::tests::dump_brand` writes.

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

const brandDir = process.env.VLPDS_SHOTS_BRAND
const servers = [await serve(5731), await serve(5732, { VLPDS_MOCK_LEVEL: '1' })]
if (brandDir) servers.push(await serve(5733, { VLPDS_MOCK_BRAND: resolve(brandDir) }))
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

// connected apps: the four testdata/oauth apps as cards, as loaded and with stream.place's
// permissions opened; no sideways scroll, every Revoke inside the viewport
for (const [w, theme, tag] of [[1280, 'light', 'desktop'], [1280, 'dark', 'desktop-dark'], [390, 'light', 'phone'], [390, 'dark', 'phone-dark']]) {
  const pg = await page('', { w, theme, account: true })
  await pg.goto('http://localhost:5731/account/security')
  const apps = pg.locator('#oauth')
  await apps.getByText('graysky.app').first().waitFor()
  await apps.scrollIntoViewIfNeeded()
  await shot(pg, `apps-${tag}`, '#oauth')
  const wide = await pg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  if (wide > 0) (failures++, console.error(`apps-${tag}: ${wide} px of sideways scroll`))
  for (const b of await apps.getByRole('button', { name: 'Revoke' }).all()) {
    const box = await b.boundingBox()
    if (!box || box.x < 0 || box.x + box.width > w) (failures++, console.error(`apps-${tag}: Revoke outside the viewport`, box))
  }
  const card = apps.locator('.app-card').first()
  await card.locator('.perm-all > summary').click()
  for (const s of await card.locator('.perm-row > summary').all()) await s.click()
  await shot(pg, `apps-${tag}-open`, '#oauth')
  const wideOpen = await pg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  if (wideOpen > 0) (failures++, console.error(`apps-${tag}-open: ${wideOpen} px of sideways scroll`))
  await pg.context().close()
}

if (brandDir) {
  mkdirSync(`${out}/brand`, { recursive: true })
  for (const [w, theme, tag] of [[1280, 'light', 'desktop-light'], [1280, 'dark', 'desktop-dark'], [390, 'light', 'phone-light'], [390, 'dark', 'phone-dark']]) {
    for (const [path, name, account] of [['/account', 'account', true], ['/', 'landing', false]]) {
      const pg = await page('', { w, theme, account })
      await pg.goto(`http://localhost:5733${path}`)
      await pg.locator('.wordmark img.logo').waitFor()
      if (account) await pg.getByText('@alice.example.com').first().waitFor({ state: 'attached' })
      await pg.evaluate(() => document.fonts.ready)
      await pg.waitForTimeout(300)
      const got = await pg.evaluate(() => ({
        name: document.querySelector('.wordmark')?.textContent,
        accent: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(),
        links: document.querySelectorAll('.brand-links a, .footer a[href^="mailto:"]').length,
      }))
      const want = theme === 'dark' ? '#fb923c' : '#c2410c'
      if (!got.name?.startsWith('Tidepool Social') || got.accent !== want) (failures++, console.error(`brand ${name}-${tag}`, got))
      if (account && got.links !== 4) (failures++, console.error(`brand ${name}-${tag}: ${got.links} links`))
      const f = `${out}/brand/${name}-${tag}.png`
      await pg.screenshot({ path: f, fullPage: true })
      console.log(f)
      await pg.context().close()
    }
  }
}

await browser.close()
process.exit(failures ? 1 : 0)
