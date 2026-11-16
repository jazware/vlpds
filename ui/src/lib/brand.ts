// The operator's theme as the user-facing pages show it (docs/operations/theming.md). The server
// writes it into the page as a JSON data block (src/xrpc/webui.rs `theme_head`) along with the
// theme's stylesheet, so the header is right on first paint; its colors are CSS custom properties
// in /theme.css. Absent (no theme, or the operator console and docs): vlpds's own.

export type BrandLink = { label: string; url: string }
export type Brand = {
  name: string
  /** The operator set something. */
  custom: boolean
  /** Same-origin path of the logo. */
  logo?: string
  /** The logo spells the name: show it alone. */
  wordmark: boolean
  links: BrandLink[]
}

const VLPDS: Brand = { name: 'vlpds', custom: false, wordmark: false, links: [] }

const safeUrl = (u: unknown): u is string => typeof u === 'string' && /^(https?:|mailto:)/i.test(u)

export function readBrand(doc: Document): Brand {
  try {
    const raw = doc.getElementById('vlpds-brand')?.textContent
    if (!raw) return VLPDS
    const j = JSON.parse(raw) as { name?: unknown; logo?: unknown; wordmark?: unknown; links?: unknown }
    const logo = typeof j.logo === 'string' && j.logo.startsWith('/') ? j.logo : undefined
    const links = Array.isArray(j.links)
      ? j.links.filter((l): l is BrandLink => !!l && typeof l.label === 'string' && safeUrl(l.url))
      : []
    return { name: typeof j.name === 'string' && j.name ? j.name : 'vlpds', custom: true, logo, wordmark: !!logo && j.wordmark === true, links }
  } catch {
    return VLPDS
  }
}

export const brand = typeof document === 'undefined' ? VLPDS : readBrand(document)
