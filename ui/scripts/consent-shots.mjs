// Screenshots of the server-rendered consent page for the testdata/oauth apps:
// `npm run consent-shots <pagesDir> [outDir]`, where pagesDir holds the pages
// `VLPDS_ROLLUP_DUMP=<pagesDir> cargo test --lib oauth::rollup::tests::dump_rows` writes, or the
// branded pages `VLPDS_BRAND_DUMP=<pagesDir> cargo test --lib brand::tests::dump_brand` writes
// (their logo and favicon at /brand/*).
// Serves them with the page's fonts, shoots 1280 and 390 px wide in light and dark, as
// loaded and with every row opened, and exits 1 on page errors or sideways scroll.

import { chromium } from 'playwright'
import { createServer } from 'node:http'
import { mkdirSync, readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const pages = resolve(process.argv[2] ?? '')
const out = resolve(process.argv[3] ?? 'shots/consent')
mkdirSync(out, { recursive: true })
const fonts = new URL('../public/fonts/', import.meta.url).pathname
const names = readdirSync(pages).filter((f) => f.endsWith('.html')).map((f) => f.slice(0, -5))
if (!names.length) throw new Error(`no pages in ${pages}`)

const server = createServer((req, res) => {
  const path = decodeURIComponent((req.url ?? '/').split('?')[0])
  try {
    if (path.startsWith('/fonts/')) {
      res.setHeader('content-type', 'font/woff2')
      return res.end(readFileSync(join(fonts, path.slice(7).replace(/\.\./g, ''))))
    }
    if (path === '/brand/logo' || path === '/brand/favicon') {
      res.setHeader('content-type', 'image/png')
      return res.end(readFileSync(join(pages, path.slice(1))))
    }
    res.setHeader('content-type', 'text/html; charset=utf-8')
    res.end(readFileSync(join(pages, path.slice(1).replace(/\.\./g, '') + '.html')))
  } catch {
    res.statusCode = 404
    res.end()
  }
})
await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
const base = `http://127.0.0.1:${server.address().port}`

const browser = await chromium.launch()
let failures = 0
for (const name of names) {
  for (const [w, theme] of [[1280, 'light'], [1280, 'dark'], [390, 'light'], [390, 'dark']]) {
    const ctx = await browser.newContext({ viewport: { width: w, height: 900 }, colorScheme: theme, deviceScaleFactor: w < 500 ? 2 : 1 })
    const pg = await ctx.newPage()
    pg.on('pageerror', (e) => (failures++, console.error('pageerror', name, e.message)))
    await pg.goto(`${base}/${name}`)
    await pg.evaluate(() => document.fonts.ready)
    const tag = `${name}-${w < 500 ? 'phone' : 'desktop'}-${theme}`
    await pg.screenshot({ path: `${out}/${tag}.png`, fullPage: true })
    await pg.evaluate(() => document.querySelectorAll('details').forEach((d) => (d.open = true)))
    await pg.screenshot({ path: `${out}/${tag}-open.png`, fullPage: true })
    const wide = await pg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    if (wide > 0) (failures++, console.error(`${tag}: ${wide} px of sideways scroll`))
    console.log(`${out}/${tag}.png`)
    await ctx.close()
  }
}
await browser.close()
server.close()
process.exit(failures ? 1 : 0)
