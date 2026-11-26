import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readBrand, VLPDS } from '../src/lib/brand.ts'

const doc = (text?: string) => ({ getElementById: (id: string) => (id === 'vlpds-brand' && text !== undefined ? ({ textContent: text } as HTMLElement) : null) })

test('no data block is vlpds', () => {
  assert.deepEqual(readBrand(doc()), VLPDS)
  assert.deepEqual(readBrand(doc('{not json')), VLPDS)
})

test('reads name, logo and links, dropping unsafe ones', () => {
  const b = readBrand(
    doc(
      JSON.stringify({
        name: 'Tidepool',
        label: 'Tidepool',
        logo: '/brand/logo?v=1',
        links: [
          { label: 'Home', url: 'https://tidepool.example' },
          { label: 'Support', url: 'mailto:help@tidepool.example' },
          { label: 'Bad', url: 'javascript:alert(1)' },
          { label: 'Plain', url: 'http://x.example' },
        ],
      }),
    ),
  )
  assert.equal(b.custom, true)
  assert.equal(b.name, 'Tidepool')
  assert.equal(b.logo, '/brand/logo?v=1')
  assert.deepEqual(b.links.map((l) => l.label), ['Home', 'Support'])
})

test('a logo off this origin is ignored; no name falls back to the label', () => {
  const b = readBrand(doc(JSON.stringify({ name: null, label: 'pds.example.com', logo: 'https://evil.example/x.png', links: [] })))
  assert.equal(b.logo, undefined)
  assert.equal(b.name, undefined)
  assert.equal(b.label, 'pds.example.com')
})
