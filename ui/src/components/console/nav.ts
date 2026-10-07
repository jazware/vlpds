import { navigate, useSearch } from '../../lib/router'

// Where the console keeps "which row is open": the slide-over is ?open=<type>:<id> on the
// current page (so it survives a reload and the back button closes it), and every detail kind
// also has a full page at /admin/<section>/<type>/<id>.

export type PanelRef = { type: string; id: string }

export function panelOf(search: URLSearchParams): PanelRef | undefined {
  const v = search.get('open')
  if (!v) return undefined
  const i = v.indexOf(':')
  return i > 0 ? { type: v.slice(0, i), id: v.slice(i + 1) } : undefined
}

export const usePanel = () => panelOf(useSearch())

export const panelParam = (type: string, id: string) => `${type}:${id}`

function withSearch(mut: (s: URLSearchParams) => void, replace: boolean) {
  const s = new URLSearchParams(location.search)
  mut(s)
  const q = s.toString()
  navigate(`${location.pathname}${q ? `?${q}` : ''}`, { replace })
}

/** Opens a row in the slide-over. `replace` while stepping through rows with j/k. */
export function openPanel(type: string, id: string, opts: { replace?: boolean } = {}) {
  const cur = panelOf(new URLSearchParams(location.search))
  withSearch((s) => s.set('open', panelParam(type, id)), opts.replace ?? !!cur)
}

export function closePanel() {
  withSearch((s) => s.delete('open'), true)
}

/** The full-page path of a detail; `section` is the owning section's path. */
export const fullPath = (sectionPath: string, type: string, id: string) => `${sectionPath}/${type}/${encodeURIComponent(id)}`
