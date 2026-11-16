import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readBrand } from '../src/lib/brand.ts'
import { autoText, contrast, mix, normalize, resolve, warnings, type Resolved } from '../src/lib/console/themeColors.ts'

// vlpds's own values, as getTheme's `defaults` gives them (src/theme.rs LIGHT / DARK)
const defaults: Record<'light' | 'dark', Resolved> = {
  light: { primary: '#17705f', primaryText: '#ffffff', secondary: '#a86d0a', accent: '#3561c9', background: '#edefea', surface: '#f8f9f6' },
  dark: { primary: '#4fbf9f', primaryText: '#0b1a15', secondary: '#e3a43a', accent: '#8fb0ff', background: '#121820', surface: '#19212b' },
}

test('colors normalize as the server does', () => {
  assert.equal(normalize('#ABC'), '#aabbcc')
  assert.equal(normalize(' #0F766E '), '#0f766e')
  for (const bad of ['0f766e', '#0f766', 'red', '#12345;', '']) assert.equal(normalize(bad), undefined, bad)
})

test('contrast and the automatic text color match src/theme.rs', () => {
  assert.equal(contrast('#000000', '#ffffff'), 21)
  assert.equal(contrast('#ffffff', '#ffffff'), 1)
  assert.equal(autoText('#0f766e'), '#ffffff')
  assert.equal(autoText('#2dd4bf'), '#101418')
  assert.equal(mix('#ffffff', '#000000', 0.5), '#808080')
  const r = resolve({ primary: '#0f766e' }, defaults.light)
  assert.deepEqual([r.primary, r.primaryText, r.secondary], ['#0f766e', '#ffffff', '#a86d0a'])
})

test('warnings: only what the theme set, against WCAG AA', () => {
  assert.deepEqual(warnings({ light: {}, dark: {} }, defaults), [])
  assert.deepEqual(warnings({ light: { primary: '#0f766e' }, dark: { primary: '#2dd4bf', secondary: '#fa0' } }, defaults), [])
  const w = warnings({ light: { primary: '#7dd3c0', primaryText: '#ffffff' }, dark: { accent: '#1a2030' } }, defaults)
  assert.deepEqual(
    w.map((x) => [x.mode, x.check]),
    [
      ['light', 'primaryText'],
      ['light', 'primaryOnSurface'],
      ['dark', 'accent'],
    ],
  )
})

function fakeDoc(text?: string) {
  return { getElementById: (id: string) => (id === 'vlpds-brand' && text !== undefined ? { textContent: text } : null) } as unknown as Document
}

test('the page brand: vlpds without the data block, and only safe links with it', () => {
  assert.deepEqual(readBrand(fakeDoc()), { name: 'vlpds', custom: false, wordmark: false, links: [] })
  assert.equal(readBrand(fakeDoc('{not json')).name, 'vlpds')
  const b = readBrand(
    fakeDoc(
      JSON.stringify({
        name: 'cavu',
        logo: '/theme/logo?v=abc',
        wordmark: true,
        links: [
          { label: 'Terms', url: 'https://cavu.example/terms' },
          { label: 'Bad', url: 'javascript:alert(1)' },
          { label: 'Support', url: 'mailto:help@cavu.example' },
        ],
      }),
    ),
  )
  assert.deepEqual(b, {
    name: 'cavu',
    custom: true,
    logo: '/theme/logo?v=abc',
    wordmark: true,
    links: [
      { label: 'Terms', url: 'https://cavu.example/terms' },
      { label: 'Support', url: 'mailto:help@cavu.example' },
    ],
  })
  // a logo that isn't same-origin is ignored, and with it the wordmark
  const o = readBrand(fakeDoc(JSON.stringify({ name: 'x', logo: 'https://evil.example/a.png', wordmark: true })))
  assert.deepEqual([o.logo, o.wordmark], [undefined, false])
})
