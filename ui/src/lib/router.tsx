import { useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent } from 'react'

// A tiny history router: the server serves index.html for /, /account/* and
// /admin/*; everything else (xrpc, oauth) is a real server route.

const listeners = new Set<() => void>()
const notify = () => listeners.forEach((l) => l())
window.addEventListener('popstate', notify)

export function navigate(to: string, opts: { replace?: boolean } = {}) {
  if (to === location.pathname + location.search) return
  if (opts.replace) history.replaceState(null, '', to)
  else history.pushState(null, '', to)
  window.scrollTo(0, 0)
  notify()
}

/** After the address bar was changed outside {@link navigate} (history.replaceState). */
export const syncRoute = () => notify()

function subscribe(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

export function usePath(): string {
  return useSyncExternalStore(subscribe, () => location.pathname)
}

export function useHash(): string {
  return useSyncExternalStore(subscribe, () => location.hash)
}

export function useSearch(): URLSearchParams {
  const s = useSyncExternalStore(subscribe, () => location.search)
  return new URLSearchParams(s)
}

/** Matches `pattern` (":name" segments, a trailing "*" takes the rest). */
export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/').filter(Boolean)
  const s = path.split('/').filter(Boolean)
  const out: Record<string, string> = {}
  for (let i = 0; i < p.length; i++) {
    if (p[i] === '*') {
      out['*'] = s.slice(i).map(decodeURIComponent).join('/')
      return out
    }
    if (i >= s.length) return null
    if (p[i].startsWith(':')) out[p[i].slice(1)] = decodeURIComponent(s[i])
    else if (p[i] !== s[i]) return null
  }
  return s.length === p.length ? out : null
}

type LinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }

export function Link({ to, onClick, ...rest }: LinkProps) {
  const handle = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e)
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    navigate(to)
  }
  return <a href={to} onClick={handle} {...rest} />
}
