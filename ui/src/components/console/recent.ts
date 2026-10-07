// The details opened in this tab, newest first, for ⌘K's "Recent". Kept in sessionStorage next to
// the admin token, so it never outlives the tab.

export type RecentItem = { type: string; id: string; title: string; kind: string; at: number }

const KEY = 'vlpds.console.recent'
const MAX = 6

export function recentDetails(): RecentItem[] {
  try {
    const v = JSON.parse(sessionStorage.getItem(KEY) ?? '[]')
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}

export function noteDetail(item: Omit<RecentItem, 'at'>) {
  const rest = recentDetails().filter((x) => x.type !== item.type || x.id !== item.id)
  try {
    sessionStorage.setItem(KEY, JSON.stringify([{ ...item, at: Date.now() }, ...rest].slice(0, MAX)))
  } catch {
    /* per-tab convenience only */
  }
}
