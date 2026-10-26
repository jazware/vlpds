// The theme's color rules, as src/theme.rs has them: normalizing, WCAG contrast, the automatic
// text color on a primary, and the warnings. Pure, so test/theme.test.ts runs them in node.

export type Mode = 'light' | 'dark'
export type ColorKey = 'primary' | 'primaryText' | 'secondary' | 'accent'
export type Palette = Partial<Record<ColorKey, string>>
export type Resolved = Record<ColorKey, string> & { background: string; surface: string }
export type Warning = { mode: Mode; check: string; ratio: number; min: number; message: string }

export const HEX = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i

export function normalize(c: string | undefined): string | undefined {
  const s = c?.trim()
  if (!s || !HEX.test(s)) return undefined
  const h = s.slice(1).toLowerCase()
  return `#${h.length === 3 ? [...h].map((x) => x + x).join('') : h}`
}

function luminance(hex: string) {
  const n = (i: number) => {
    const v = parseInt(hex.slice(1 + i, 3 + i), 16) / 255
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * n(0) + 0.7152 * n(2) + 0.0722 * n(4)
}

export function contrast(a: string, b: string) {
  const [x, y] = [luminance(a), luminance(b)]
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)
}

export const autoText = (bg: string) => (contrast('#ffffff', bg) >= contrast('#101418', bg) ? '#ffffff' : '#101418')

export function mix(a: string, b: string, t: number) {
  const ch = (h: string, i: number) => parseInt(h.slice(1 + i, 3 + i), 16)
  const m = (i: number) => Math.round(ch(a, i) * t + ch(b, i) * (1 - t)).toString(16).padStart(2, '0')
  return `#${m(0)}${m(2)}${m(4)}`
}

/** One mode as the pages will show it: the draft's colors, vlpds's for the rest. */
export function resolve(p: Palette, d: Resolved): Resolved {
  const primary = normalize(p.primary)
  const text = normalize(p.primaryText)
  return {
    primary: primary ?? d.primary,
    primaryText: text ?? (primary ? autoText(primary) : d.primaryText),
    secondary: normalize(p.secondary) ?? d.secondary,
    accent: normalize(p.accent) ?? d.accent,
    background: d.background,
    surface: d.surface,
  }
}

export function warnings(colors: Record<Mode, Palette>, defaults: Record<Mode, Resolved>): Warning[] {
  const out: Warning[] = []
  for (const mode of ['light', 'dark'] as Mode[]) {
    const p = colors[mode]
    const r = resolve(p, defaults[mode])
    const check = (check: string, fg: string, bg: string, min: number, what: string) => {
      const ratio = contrast(fg, bg)
      if (ratio < min) out.push({ mode, check, ratio: Math.round(ratio * 100) / 100, min, message: `${mode}: ${what} is ${ratio.toFixed(2)}:1, under WCAG AA's ${min}:1` })
    }
    if (normalize(p.primary)) {
      check('primaryText', r.primaryText, r.primary, 4.5, `text ${r.primaryText} on primary ${r.primary}`)
      check('primaryOnSurface', r.primary, r.surface, 4.5, `primary ${r.primary} as link text on ${r.surface}`)
    }
    if (normalize(p.accent)) check('accent', r.accent, r.background, 3, `the focus ring ${r.accent} on ${r.background}`)
  }
  return out
}

