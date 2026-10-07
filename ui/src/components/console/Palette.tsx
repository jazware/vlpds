import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { listAccounts } from '../../lib/adminApi'
import { withAdmin } from '../../lib/console/adminAdapter'
import { relTime } from '../../lib/format'
import { navigate } from '../../lib/router'
import { openPanel } from './nav'
import { Kbd } from './kit'
import { recentDetails } from './recent'

// ⌘K. Items come from providers: the shell's (sections, actions, nodes, lookups) and any a
// section registers with registerPalette(). A provider gets the query and returns items now,
// and may return more later (`async`) for lookups that need the server.

export type PalItem = {
  group: string
  title: string
  desc?: string
  glyph?: ReactNode
  keys?: string[]
  /** Extra text to match on (DIDs, emails) besides the title and description. */
  hay?: string
  /** Shown for an empty query too (sections, a few actions). */
  always?: boolean
  run: () => void
}
export type PalProvider = {
  items: (q: string) => PalItem[]
  async?: (q: string, signal: AbortSignal) => Promise<PalItem[]>
}

const providers = new Set<PalProvider>()
export function registerPalette(p: PalProvider) {
  providers.add(p)
  return () => {
    providers.delete(p)
  }
}

let openState = false
const subs = new Set<() => void>()
export const isPaletteOpen = () => openState
export function setPaletteOpen(v: boolean) {
  openState = v
  subs.forEach((l) => l())
}

/** What an empty palette opens on: one item per live banner, then the details opened lately. */
export const ATTENTION = 'Needs attention'
export const RECENT = 'Recent'

const ORDER = [ATTENTION, RECENT, 'Look up', 'Actions', 'Go to', 'Accounts', 'Nodes', 'Firehose']

const RECENT_GLYPH: Record<string, string> = { account: '@', node: '◆', shard: '▦', case: '▤', subject: '⚑', audit: '≡', sub: '≋', relay: '⇄', bucket: '◔', mail: '✉' }

/** The last six details opened in this tab (recent.ts). */
const recentProvider: PalProvider = {
  items: () =>
    recentDetails().map((r) => ({
      group: RECENT,
      glyph: RECENT_GLYPH[r.type] ?? '›',
      title: r.title,
      desc: `${r.kind.toLowerCase()} · ${relTime(r.at)}`,
      hay: r.id,
      always: true,
      run: () => openPanel(r.type, r.id),
    })),
}
providers.add(recentProvider)
const rank = (g: string) => {
  const i = ORDER.indexOf(g)
  return i < 0 ? ORDER.length : i
}

function score(x: PalItem, q: string): number {
  const t = x.title.toLowerCase()
  const h = `${x.desc ?? ''} ${x.hay ?? ''}`.toLowerCase()
  if (t.startsWith(q) || t.startsWith(`@${q}`)) return 4
  if (t.split(/[\s.@:/-]/).some((w) => w.startsWith(q))) return 3
  if (t.includes(q)) return 2
  if (h.includes(q)) return 1
  return 0
}

function highlight(t: string, q: string): ReactNode {
  if (!q) return t
  const i = t.toLowerCase().indexOf(q.toLowerCase())
  if (i < 0) return t
  return (
    <>
      {t.slice(0, i)}
      <mark>{t.slice(i, i + q.length)}</mark>
      {t.slice(i + q.length)}
    </>
  )
}

/** Lookups every console has: a DID, an at:// URI or bsky.app link, a handle, an email prefix. */
export const lookupProvider: PalProvider = {
  items: (q) => {
    const out: PalItem[] = []
    if (q.startsWith('did:'))
      out.push({ group: 'Look up', glyph: '⌕', title: `Open account ${q.length > 40 ? `${q.slice(0, 40)}…` : q}`, desc: 'getAccountInfo', run: () => openPanel('account', q) })
    if (/^(at:\/\/|https:\/\/bsky\.app\/)/.test(q))
      out.push({ group: 'Look up', glyph: '⌕', title: `Look up “${q.length > 48 ? `${q.slice(0, 48)}…` : q}”`, desc: 'in Moderation', run: () => navigate(`/admin/moderation?q=${encodeURIComponent(q)}`) })
    return out
  },
  // accounts on this PDS by handle prefix, email prefix or DID
  async: async (q, signal) => {
    const v = q.replace(/^@/, '')
    if (v.length < 2 || /\s/.test(v) || v.includes('://')) return []
    const r = await withAdmin((c) => listAccounts(c, { q: v, limit: 8 }, signal))
    return r.accounts.map((a) => ({
      group: 'Accounts',
      glyph: '@',
      title: `@${a.handle}`,
      desc: `${a.email ?? a.did}${a.status === 'active' ? '' : ` · ${a.status}`}`,
      hay: `${a.did} ${a.email ?? ''} ${a.handle}`,
      run: () => openPanel('account', a.did),
    }))
  },
}

const subscribeOpen = (l: () => void) => {
  subs.add(l)
  return () => {
    subs.delete(l)
  }
}
export const usePaletteOpen = () => useSyncExternalStore(subscribeOpen, () => openState)

export function Palette() {
  const open = usePaletteOpen()
  if (!open) return null
  return <PaletteInner />
}

function PaletteInner() {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const [extra, setExtra] = useState<PalItem[]>([])
  const input = useRef<HTMLInputElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const ql = q.trim().toLowerCase()

  useEffect(() => {
    setExtra([])
    const qq = q.trim()
    if (!qq) return
    const ac = new AbortController()
    const t = setTimeout(async () => {
      const got = await Promise.all([...providers].filter((p) => p.async).map((p) => p.async!(qq, ac.signal).catch(() => [] as PalItem[])))
      if (!ac.signal.aborted) setExtra(got.flat())
    }, 180)
    return () => {
      ac.abort()
      clearTimeout(t)
    }
  }, [q])

  // the attention items follow the shell's polls while the palette is open
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (ql) return
    const t = setInterval(() => setTick((n) => n + 1), 2000)
    return () => clearInterval(t)
  }, [ql])

  const items = useMemo(() => {
    const all = [...providers].flatMap((p) => p.items(q.trim()))
    let shown: PalItem[]
    if (!ql) {
      const inbox = all.filter((x) => x.group === ATTENTION || x.group === RECENT)
      // sections and actions stay a keystroke away; they open the palette only when nothing else would
      shown = inbox.length ? inbox : all.filter((x) => x.always)
    } else {
      const direct = all.filter((x) => x.group === 'Look up')
      const scored = all
        .filter((x) => x.group !== 'Look up')
        .map((x) => ({ x, s: score(x, ql) }))
        .filter((y) => y.s > 0)
        .sort((a, b) => b.s - a.s)
        .slice(0, 40)
        .map((y) => y.x)
      shown = [...direct, ...scored, ...extra.filter((e) => !scored.some((s) => s.title === e.title))]
    }
    return shown.map((x, i) => ({ x, i })).sort((a, b) => rank(a.x.group) - rank(b.x.group) || a.i - b.i).map((y) => y.x)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, ql, extra, tick])
  const inboxOnly = !ql && items.some((x) => x.group === ATTENTION || x.group === RECENT)

  useEffect(() => {
    setIdx((i) => Math.min(i, Math.max(0, items.length - 1)))
  }, [items.length])
  useEffect(() => {
    list.current?.querySelector('.cx-pi.on')?.scrollIntoView({ block: 'nearest' })
  }, [idx])

  const run = (i: number) => {
    const x = items[i]
    if (!x) return
    setPaletteOpen(false)
    x.run()
  }
  let group = ''
  return (
    <div
      className="cx-scrim"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) setPaletteOpen(false)
      }}
    >
      <div className="cx-pal" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="pin">
          <svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true">
            <circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="M11 11l3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
          <input
            ref={input}
            autoFocus
            value={q}
            placeholder="Handle, DID, email, node, or an action like “finalize”"
            autoComplete="off"
            spellCheck={false}
            aria-label="Search"
            role="combobox"
            aria-expanded="true"
            aria-controls="cx-pal-list"
            onChange={(e) => {
              setQ(e.target.value)
              setIdx(0)
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) {
                e.preventDefault()
                setIdx((i) => Math.min(items.length - 1, i + 1))
              } else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) {
                e.preventDefault()
                setIdx((i) => Math.max(0, i - 1))
              } else if (e.key === 'Enter') {
                e.preventDefault()
                run(idx)
              } else if (e.key === 'Escape') {
                e.preventDefault()
                e.stopPropagation()
                setPaletteOpen(false)
              }
            }}
          />
          <kbd>esc</kbd>
        </div>
        <div className="list" id="cx-pal-list" role="listbox" ref={list}>
          {items.map((x, i) => {
            const head = x.group !== group
            group = x.group
            return (
              <div key={`${x.group}:${x.title}:${i}`}>
                {head && <div className="cx-gh">{x.group}</div>}
                <div className={`cx-pi${i === idx ? ' on' : ''}`} role="option" aria-selected={i === idx} onMouseMove={() => setIdx(i)} onClick={() => run(i)}>
                  <span className="pg">{x.glyph ?? '›'}</span>
                  <span className="pt">{highlight(x.title, q.trim())}</span>
                  {x.desc && <span className="pd">{x.desc}</span>}
                  {x.keys && (
                    <span className="pk">
                      <Kbd k={x.keys} />
                    </span>
                  )}
                </div>
              </div>
            )
          })}
          {inboxOnly && (
            <>
              <div className="cx-gh">Go to · Actions</div>
              <div className="cx-pi hint" aria-hidden="true">
                <span className="pg">○</span>
                <span className="pt muted">Type to search sections and actions</span>
                <span className="pk">
                  <Kbd k="g" />
                </span>
              </div>
            </>
          )}
          {!items.length && <div className="cx-empty">{ql ? `Nothing matches “${q.trim()}”. Try a handle, a DID, an email or a node.` : 'Type to search.'}</div>}
        </div>
        <div className="pfoot">
          <span>
            <Kbd k={['↑', '↓']} /> move
          </span>
          <span>
            <Kbd k="↵" /> open
          </span>
          <span>
            <Kbd k="g" /> then a letter jumps to a section
          </span>
          <span style={{ marginLeft: 'auto' }}>
            <Kbd k="?" /> all shortcuts
          </span>
        </div>
      </div>
    </div>
  )
}
