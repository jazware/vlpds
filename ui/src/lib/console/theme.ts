import { admin } from '../xrpc'
import { K } from './keys'
import { mutate } from './mutate'
import { shared } from './query'
import type { Mode, Palette, Resolved } from './themeColors'

export * from './themeColors'

// The operator's theme (docs/operations/theming.md): one config object, read with getTheme and
// replaced with putTheme against its `version` (ifVersion). Images go up inline as data: URIs; the
// view names them by hash and URL. Contrast is checked here as the server does (src/theme.rs), so
// the preview warns before anything is saved.

export type Font = 'default' | 'system' | 'serif' | 'rounded' | 'mono'
export type LinkKey = 'home' | 'terms' | 'privacy' | 'support'
export type ImageView = { mime: string; sha256: string; bytes: number; url: string } | null

export type ThemeView = {
  theme: {
    name?: string | null
    logoIsWordmark: boolean
    colors: Record<Mode, Palette>
    font: Font
    links: Partial<Record<LinkKey, string>>
    logo: ImageView
    favicon: ImageView
  }
  version: number
  updatedAt?: string
  updatedBy?: string
  warnings: import('./themeColors').Warning[]
  resolved: Record<Mode, Resolved>
  defaults: Record<Mode, Resolved>
  stylesheet: string
  fallbacks: Record<string, string | null | undefined>
  limits: { nameChars: number; urlChars: number; logoBytes: number; faviconBytes: number; logoTypes: string[]; faviconTypes: string[]; fonts: Font[] }
}

export const themeQ = shared({
  key: K.theme,
  fn: (signal) => admin<ThemeView>('vlpds.admin.getTheme', { signal }),
  poll: 60_000,
  version: (d) => d.version,
})

/** An image change: undefined keeps the stored one, null removes it, a data: URI replaces it. */
export type ImageEdit = undefined | null | string

export type Draft = {
  name: string
  logoIsWordmark: boolean
  colors: Record<Mode, Palette>
  font: Font
  links: Partial<Record<LinkKey, string>>
  logo: ImageEdit
  favicon: ImageEdit
}

export function draftOf(v: ThemeView): Draft {
  const t = v.theme
  return {
    name: t.name ?? '',
    logoIsWordmark: t.logoIsWordmark,
    colors: { light: { ...t.colors.light }, dark: { ...t.colors.dark } },
    font: t.font,
    links: { ...t.links },
    logo: undefined,
    favicon: undefined,
  }
}

const clean = <T extends Record<string, string | undefined>>(o: T) => Object.fromEntries(Object.entries(o).filter(([, v]) => v && v.trim())) as T

export function bodyOf(d: Draft) {
  const theme: Record<string, unknown> = {
    name: d.name.trim() || null,
    logoIsWordmark: d.logoIsWordmark,
    colors: { light: clean(d.colors.light), dark: clean(d.colors.dark) },
    font: d.font,
    links: clean(d.links),
  }
  if (d.logo !== undefined) theme.logo = d.logo
  if (d.favicon !== undefined) theme.favicon = d.favicon
  return theme
}

export const VLPDS: Draft = { name: '', logoIsWordmark: false, colors: { light: {}, dark: {} }, font: 'default', links: {}, logo: null, favicon: null }

export type Saved = ThemeView & { changes: string[] }

export function saveTheme(d: Draft, o: { ifVersion: number; note?: string; actor?: string }): Promise<Saved> {
  return mutate({
    run: () => admin<Saved>('vlpds.admin.putTheme', { body: { theme: bodyOf(d), ifVersion: o.ifVersion, note: o.note?.trim() || undefined, actor: o.actor?.trim() || undefined } }),
    changes: [{ kind: 'config', id: 'theme' }],
  })
}

/** Sniffs a file's first bytes as the server does: png, jpeg, webp, ico. */
export async function sniff(f: Blob): Promise<string | undefined> {
  const b = new Uint8Array(await f.slice(0, 12).arrayBuffer())
  const at = (i: number, s: string) => [...s].every((c, j) => b[i + j] === c.charCodeAt(0))
  if (b[0] === 0x89 && at(1, 'PNG')) return 'image/png'
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg'
  if (at(0, 'RIFF') && at(8, 'WEBP')) return 'image/webp'
  if (b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0) return 'image/x-icon'
  return undefined
}

export function dataUri(f: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(String(r.result))
    r.onerror = () => reject(r.error)
    r.readAsDataURL(f)
  })
}
