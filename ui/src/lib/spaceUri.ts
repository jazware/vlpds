// Space URIs, apart from spaces.ts so they load without the app around them.

export const spaceUri = (authority: string, type: string, skey: string) => `at:space/${authority}/${type}/${skey}`

/**
 * A space URI, or a record in one: `at:space/{authority}/{type}/{skey}[/{author}/{collection}/{rkey}]`,
 * or the form before the Nov 24 alpha (`at://{authority}/space/...`) that old links, audit entries and
 * hosts not yet upgraded still carry. `space` is always the current form.
 */
export function spaceUriParts(s: string) {
  const m = /^at:(?:space\/([^/]+)|\/\/([^/]+)\/space)\/([^/]+)\/([^/]+)(?:\/([^/]+)\/([^/]+)\/([^/]+))?\/?$/.exec(s.trim())
  if (!m) return null
  const authority = m[1] ?? m[2]
  const record = m[5] ? { author: m[5], collection: m[6], rkey: m[7] } : undefined
  return { space: spaceUri(authority, m[3], m[4]), authority, type: m[3], skey: m[4], record }
}
