// The operator's branding (docs/operations/branding.md). The server writes it into the landing,
// account, sign-up and /migrate shells as a JSON data block (src/brand.rs `spa_head`), with its
// accent stylesheet, so the header is right on first paint. Absent (unbranded, or the operator
// console and the docs): vlpds's own.

export type BrandLink = { label: string; url: string }
export type Brand = {
  /** The operator set something. */
  custom: boolean
  /** The operator's name, if set. */
  name?: string
  /** The name, else the host: the logo's alt text. */
  label: string
  /** Same-origin path of the logo. */
  logo?: string
  links: BrandLink[]
}

export const VLPDS: Brand = { custom: false, label: 'vlpds', links: [] }

const safeUrl = (u: unknown): u is string => typeof u === 'string' && /^(https:|mailto:)/i.test(u)

export function readBrand(doc: Pick<Document, 'getElementById'>): Brand {
  try {
    const raw = doc.getElementById('vlpds-brand')?.textContent
    if (!raw) return VLPDS
    const j = JSON.parse(raw) as { name?: unknown; label?: unknown; logo?: unknown; links?: unknown }
    const name = typeof j.name === 'string' && j.name ? j.name : undefined
    const logo = typeof j.logo === 'string' && j.logo.startsWith('/brand/') ? j.logo : undefined
    const links = Array.isArray(j.links)
      ? j.links.filter((l): l is BrandLink => !!l && typeof l.label === 'string' && safeUrl(l.url))
      : []
    const label = name ?? (typeof j.label === 'string' && j.label ? j.label : 'vlpds')
    return { custom: true, name, label, logo, links }
  } catch {
    return VLPDS
  }
}

export const brand = typeof document === 'undefined' ? VLPDS : readBrand(document)
