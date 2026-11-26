import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spaceUri, spaceUriParts } from '../src/lib/spaceUri.ts'

const SPACE = 'at:space/did:plc:abc/com.example.group/main'

test('space URIs read in either form and print in the current one', () => {
  assert.equal(spaceUri('did:plc:abc', 'com.example.group', 'main'), SPACE)
  for (const s of [SPACE, 'at://did:plc:abc/space/com.example.group/main']) {
    assert.deepEqual(spaceUriParts(s), { space: SPACE, authority: 'did:plc:abc', type: 'com.example.group', skey: 'main', record: undefined })
  }
  const rec = spaceUriParts('at://did:plc:abc/space/com.example.group/main/did:plc:bob/com.example.post/3k')
  assert.deepEqual(rec?.record, { author: 'did:plc:bob', collection: 'com.example.post', rkey: '3k' })
  assert.equal(rec?.space, SPACE)
  for (const bad of ['at://did:plc:abc/com.example.post/3k', 'at:space/did:plc:abc/com.example.group', 'nope']) assert.equal(spaceUriParts(bad), null, bad)
})
