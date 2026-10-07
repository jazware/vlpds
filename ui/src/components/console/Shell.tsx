import { useEffect, useRef, type ReactNode } from 'react'
import { useClusterView, clusterPoll, clusterView } from '../../lib/console/cluster'
import { releaseHeld } from '../../lib/console/firehose'
import { getLive, togglePaused, toggleSources, useLiveState } from '../../lib/console/live'
import { ago, clock, dur, factorName, plural } from '../../lib/console/fmt'
import { isSlow, lockoutsPoll, openCasesPoll, subscribersPoll } from '../../lib/console/polls'
import { heldSignInKeys, KEY_SHORT, rlPoll, shortName } from '../../lib/console/ratelimits'
import { crawlersPoll } from '../../lib/console/sys'
import { setTheme, useResolvedTheme } from '../../lib/hooks'
import { Link, navigate, usePath } from '../../lib/router'
import { setAdminToken } from '../../lib/xrpc'
import { closeDialog, DialogHost, isDialogOpen, openDialog } from './dialogs'
import { detailPath, Drawer } from './Drawer'
import { GLYPH, Kbd, Swatch, type Tone } from './kit'
import { closePanel, openPanel, panelOf } from './nav'
import { ATTENTION, isPaletteOpen, lookupProvider, Palette, registerPalette, setPaletteOpen, usePaletteOpen, type PalItem } from './Palette'
import { SECTION, SECTIONS, TABBAR, type Section, type SectionId } from './sections'
import { Toasts } from './toast'

// The frame around every console page: top bar with the strata rule, the section rail (a tab
// bar on phones), the stale banner, and the hosts for the slide-over, palette, dialogs and
// toasts. Owns the keyboard.

const Mark = () => (
  <svg width="22" height="18" viewBox="0 0 22 18" aria-hidden="true">
    <rect x="0" y="0" width="22" height="4" rx="1" fill="currentColor" />
    <rect x="3" y="7" width="16" height="4" rx="1" fill="currentColor" opacity=".6" />
    <rect x="6" y="14" width="10" height="4" rx="1" fill="var(--amber)" opacity=".85" />
  </svg>
)

function useTheme() {
  const t = useResolvedTheme()
  return { theme: t, toggle: () => setTheme(t === 'dark' ? 'light' : 'dark') }
}

const lock = () => setAdminToken(null)

export function shortcutsDialog() {
  const rows: [string[], string][] = [
    [['⌘', 'K'], 'Command palette: sections, accounts, nodes, actions'],
    ...SECTIONS.map((s): [string[], string] => [['g', s.key], s.label]),
    [['j', 'k'], 'Move through rows'],
    [['↵'], 'Open the row in a panel'],
    [['o'], 'Open the panel as a full page'],
    [['/'], 'Search on this page'],
    [['space'], 'Pause or resume live updates'],
    [['t'], 'Toggle light / dark'],
    [['esc'], 'Close the panel, dialog or full page'],
  ]
  openDialog((close) => (
    <div className="cx-dlg" role="dialog" aria-modal="true" aria-labelledby="cx-dlg-t">
      <div className="dh">
        <div className="ico" aria-hidden="true">
          ⌘
        </div>
        <h2 id="cx-dlg-t">Keyboard shortcuts</h2>
      </div>
      <div className="cx-keys">
        {rows.map(([k, d]) => (
          <span key={d} style={{ display: 'contents' }}>
            <span>
              <Kbd k={k} />
            </span>
            <span>{d}</span>
          </span>
        ))}
      </div>
      <div className="df">
        <button type="button" className="cx-btn" onClick={close} autoFocus>
          Close
        </button>
      </div>
    </div>
  ))
}

function useBadges(): Partial<Record<SectionId, { k: 'warn' | 'err' | 'plain'; t: string; title?: string }>> {
  const { view } = useClusterView()
  const cases = openCasesPoll.use()
  const subs = subscribersPoll.use()
  const locks = lockoutsPoll.use()
  const down = view?.nodes.filter((n) => n.health === 'err').length ?? 0
  const slow = subs.data?.subscribers.filter(isSlow).length ?? 0
  const nCases = cases.data?.length ?? 0
  const nLocks = locks.data?.supported ? locks.data.data.length : 0
  return {
    nodes: down ? { k: 'err', t: `${down} down` } : view?.unowned ? { k: 'err', t: `${view.unowned} unowned`, title: 'Shards with no owner' } : undefined,
    firehose: slow ? { k: 'warn', t: `${slow} slow` } : undefined,
    moderation: nCases ? { k: 'warn', t: String(nCases), title: 'Open cases' } : undefined,
    limits: nLocks ? { k: 'warn', t: String(nLocks), title: 'Locked out now' } : undefined,
    spaces: { k: 'plain', t: 'alpha' },
  }
}

function Side({ current }: { current: Section }) {
  const badges = useBadges()
  const { view } = useClusterView()
  const live = useLiveState()
  let group = ''
  const v = view?.raw.version
  return (
    <aside className="cx-side" aria-label="Sections">
      {SECTIONS.map((s) => {
        const head = s.group !== group ? s.group : ''
        group = s.group
        const b = badges[s.id]
        return (
          <div key={s.id} style={{ display: 'contents' }}>
            {head && <h6>{head}</h6>}
            <Link to={s.path} className={`cx-nav${current.id === s.id ? ' on' : ''}`} title={`${s.label} (g ${s.key})`} aria-current={current.id === s.id ? 'page' : undefined}>
              <span className="ni">{s.icon}</span>
              {s.label}
              {b ? (
                <span className={`cx-badge ${b.k}`} title={b.title}>
                  {b.t}
                </span>
              ) : (
                <span className="k">g {s.key}</span>
              )}
            </Link>
          </div>
        )
      })}
      <div className="cx-sidefoot">
        {v && (
          <>
            build <span className="mono">{v.binary.rev.slice(0, 12)}</span> · level {v.active ?? '—'}
            <br />
          </>
        )}
        Admin token kept in this tab only.
        <br />
        <button type="button" className="cx-linklike" onClick={lock}>
          Lock console
        </button>{' '}
        ·{' '}
        <button type="button" className="cx-linklike" onClick={shortcutsDialog}>
          shortcuts
        </button>
        <br />
        <button type="button" className="cx-linklike" onClick={toggleSources} aria-pressed={live.showSources}>
          {live.showSources ? 'Hide data sources' : 'Show data sources'}
        </button>
      </div>
    </aside>
  )
}

function StreamChip() {
  const live = useLiveState()
  const cls = live.stale ? ' stale' : live.paused ? ' paused' : ''
  const text = live.stale ? 'not updating' : live.paused ? 'paused' : 'live'
  const det = live.stale ? `· last data ${live.lastOkAt ? dur(Date.now() - live.lastOkAt) : '—'} ago` : live.paused ? '· space to resume' : '· every 2 s'
  return (
    <button
      type="button"
      className={`cx-stream${cls}`}
      title={live.stale ? 'Retry now' : 'Live updates: click or press space to pause'}
      onClick={() => (live.stale ? clusterPoll.refresh() : togglePaused())}
    >
      <span className="dot" />
      <span>{text}</span>
      <span className="det muted mono">{det}</span>
    </button>
  )
}

const att = (tone: Tone, title: string, desc: string, run: () => void): PalItem => ({
  group: ATTENTION,
  glyph: <span className={`cx-g s-${tone}`}>{GLYPH[tone]}</span>,
  title,
  desc,
  always: true,
  run,
})

/** ⌘K's "Needs attention": one item per live banner, each opening its row. */
function attentionItems(): PalItem[] {
  const out: PalItem[] = []
  const c = clusterPoll.get().data
  const view = c ? clusterView(c) : undefined
  if (view?.unowned) out.push(att('err', `${plural(view.unowned, 'shard')} with no owner`, 'writes to them get 503 · Nodes & shards', () => navigate(SECTION.nodes.path)))
  for (const n of view?.nodes.filter((x) => x.health === 'err') ?? [])
    out.push(att('err', n.reachable ? `${n.node}'s lease is not valid` : `${n.node} doesn't answer`, 'node', () => openPanel('node', n.node)))
  if (c?.version?.mixedBuilds) out.push(att('warn', 'Mixed builds', c.version.revs.map((r) => r.slice(0, 8)).join(', '), () => navigate(SECTION.nodes.path)))
  for (const s of subscribersPoll.get().data?.subscribers.filter(isSlow) ?? [])
    out.push(att('warn', `Subscriber #${s.conn} is ${dur(s.lagMs ?? 0)} behind`, `${s.relay ?? s.userAgent.split(' ')[0] ?? s.ip ?? ''} · ${s.node}`, () => openPanel('sub', `${s.node}/${s.conn}`)))
  const cases = openCasesPoll.get().data ?? []
  if (cases.length) {
    const oldest = Math.min(...cases.map((k) => Date.parse(k.createdAt)))
    out.push(att('warn', plural(cases.length, 'open case'), `oldest ${ago(oldest).replace(' ago', '')} · Moderation`, () => navigate(SECTION.moderation.path)))
  }
  const locks = lockoutsPoll.get().data
  for (const l of locks?.supported ? locks.data : [])
    out.push(att('warn', `Sign-in codes locked for @${l.handle ?? l.did}`, `${factorName(l.factor)} · clears in ${dur(l.lockedUntil - Date.now())}`, () => openPanel('account', l.did)))
  for (const k of heldSignInKeys(rlPoll.get().data))
    out.push(
      att('err', `Sign-in held for ${k.ident ? (k.ident.includes('@') || k.ident.startsWith('did:') ? k.ident : `@${k.ident}`) : k.did}`, `${shortName(k.bucket.name)} · ${KEY_SHORT[k.bucket.key]} · clears in ${dur(k.c.resetMs - Date.now())}`, () =>
        k.did ? openPanel('account', k.did) : openPanel('bucket', k.bucket.name),
      ),
    )
  for (const r of crawlersPoll.get().data?.relays.filter((x) => x.status && !x.status.ok) ?? [])
    out.push(att('warn', `${r.relay} refused the last crawl`, `${r.status!.httpStatus ? `HTTP ${r.status!.httpStatus}` : 'unreachable'} · ${ago(r.status!.lastAttemptMs)}`, () => openPanel('relay', r.relay)))
  return out
}

/** Keeps the polls the attention items read running while the palette is open. */
function WarmAttention() {
  rlPoll.use()
  crawlersPoll.use()
  return null
}

/** The shell's own palette entries: sections, console actions, nodes, lookups. */
function useCorePalette() {
  const { view } = useClusterView()
  const viewRef = useRef(view)
  viewRef.current = view
  const { toggle } = useTheme()
  const toggleRef = useRef(toggle)
  toggleRef.current = toggle
  useEffect(() => {
    const offLookup = registerPalette(lookupProvider)
    const off = registerPalette({
      items: () => {
        const live = getLive()
        const goto: PalItem[] = SECTIONS.map((s) => ({ group: 'Go to', glyph: s.icon, title: s.label, keys: ['g', s.key], always: s.id !== 'mail' && s.id !== 'config', run: () => navigate(s.path) }))
        const acts: PalItem[] = [
          { group: 'Actions', title: live.paused ? 'Resume live updates' : 'Pause live updates', keys: ['space'], always: true, run: togglePaused },
          { group: 'Actions', title: 'Toggle light / dark', keys: ['t'], always: true, run: () => toggleRef.current() },
          { group: 'Actions', title: 'Keyboard shortcuts', keys: ['?'], always: true, run: shortcutsDialog },
          { group: 'Actions', title: 'Live metrics (all charts)', desc: 'this node’s /metrics', run: () => navigate('/admin/metrics') },
          { group: 'Actions', title: live.showSources ? 'Hide data sources' : 'Show data sources', desc: 'which endpoint feeds each panel', run: toggleSources },
          { group: 'Actions', title: 'Lock console', desc: 'forget the admin token in this tab', run: lock },
        ]
        const nodes: PalItem[] = (viewRef.current?.nodes ?? []).map((n) => ({
          group: 'Nodes',
          glyph: <Swatch color={n.color} />,
          title: n.node,
          desc: `${n.shards} shards · ${n.log}`,
          hay: n.addr,
          run: () => openPanel('node', n.node),
        }))
        const audit: PalItem = { group: 'Go to', glyph: '≡', title: 'Audit log', desc: 'every operator action · Moderation', hay: 'operator activity history', run: () => navigate(`${SECTION.moderation.path}#audit`) }
        return [...attentionItems(), ...goto, audit, ...acts, ...nodes]
      },
    })
    return () => {
      off()
      offLookup()
    }
  }, [])
}

function useKeyboard(path: string) {
  const { toggle } = useTheme()
  const kb = useRef(-1)
  const gAt = useRef(0)
  const toggleRef = useRef(toggle)
  toggleRef.current = toggle
  useEffect(() => {
    kb.current = -1
  }, [path])
  useEffect(() => {
    const rows = () =>
      [...document.querySelectorAll<HTMLElement>('.cx-view [data-open]')].filter((r) => r.offsetParent !== null && !r.closest('[hidden]'))
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(!isPaletteOpen())
        return
      }
      if (isPaletteOpen() || isDialogOpen()) return
      const t = e.target as HTMLElement
      const inField = !!t.closest?.('input,textarea,select,[contenteditable="true"]')
      if (e.key === 'Escape') {
        if (inField) return t.blur()
        const p = panelOf(new URLSearchParams(location.search))
        if (p) return closePanel()
        const m = location.pathname.match(/^(\/admin\/[^/]+)\/[^/]+\/[^/]+$/)
        if (m && document.querySelector('.cx-fullpage')) navigate(m[1])
        return
      }
      if (inField || e.metaKey || e.ctrlKey || e.altKey) return
      if (Date.now() - gAt.current < 1200) {
        gAt.current = 0
        const s = SECTIONS.find((x) => x.key === e.key)
        if (s) {
          e.preventDefault()
          navigate(s.path)
        }
        return
      }
      switch (e.key) {
        case 'g':
          gAt.current = Date.now()
          return
        case '/': {
          e.preventDefault()
          const f = document.querySelector<HTMLInputElement>('.cx-view [data-search]')
          if (f) f.focus()
          else setPaletteOpen(true)
          return
        }
        case '?':
          return shortcutsDialog()
        case 't':
          return toggleRef.current()
        case ' ':
          if (t.closest?.('button,a,summary')) return
          e.preventDefault()
          return togglePaused()
        case 'o': {
          const p = panelOf(new URLSearchParams(location.search))
          const to = p && detailPath(p.type, p.id)
          if (to) navigate(to)
          return
        }
        case 'Enter': {
          if (t.closest?.('button,a,summary')) return
          const r = rows()[kb.current]
          if (r) r.click()
          return
        }
      }
      const down = e.key === 'j' || (e.key === 'ArrowDown' && kb.current >= 0)
      const up = e.key === 'k' || (e.key === 'ArrowUp' && kb.current >= 0)
      if (!down && !up) return
      const rs = rows()
      if (!rs.length) return
      e.preventDefault()
      rs.forEach((r) => r.classList.remove('kb'))
      kb.current = Math.max(0, Math.min(rs.length - 1, kb.current + (down ? 1 : -1)))
      const r = rs[kb.current]
      r.classList.add('kb')
      r.scrollIntoView({ block: 'nearest' })
      const open = r.dataset.open ?? ''
      const i = open.indexOf(':')
      if (panelOf(new URLSearchParams(location.search)) && i > 0 && !open.startsWith('row:')) openPanel(open.slice(0, i), open.slice(i + 1), { replace: true })
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])
}

export function Shell({ section, crumbs, children }: { section: Section; crumbs?: ReactNode; children: ReactNode }) {
  const path = usePath()
  const live = useLiveState()
  const { view } = useClusterView()
  const { theme, toggle } = useTheme()
  useKeyboard(path)
  useCorePalette()
  const palOpen = usePaletteOpen()
  const wasPaused = useRef(live.paused)
  useEffect(() => {
    if (wasPaused.current && !live.paused) releaseHeld()
    wasPaused.current = live.paused
  }, [live.paused])
  // a dialog belongs to the page it was opened on
  useEffect(() => closeDialog, [path])
  const self = view?.nodes.find((n) => n.self)
  return (
    <div className={`cx${live.stale ? ' is-stale' : ''}`} data-theme-resolved={theme}>
      <header className="cx-top">
        <Link to="/admin" className="cx-wordmark" aria-label="Console overview">
          <Mark />
          vlpds<span className="where">operator · {location.host}</span>
        </Link>
        <nav className="cx-crumbs" aria-label="Breadcrumb">
          {crumbs ?? (
            <>
              {section.group && (
                <>
                  <span>{section.group}</span>
                  <span className="sep">/</span>
                </>
              )}
              <b>{section.label}</b>
            </>
          )}
        </nav>
        <div className="cx-spacer" />
        {self && !view?.single && (
          <div className="cx-via" title="The console is served by any node. Account calls are routed to each account's owner.">
            via <Swatch color={self.color} />
            <span className="mono">{self.node}</span>
          </div>
        )}
        <StreamChip />
        <button type="button" className="cx-kbtn" onClick={() => setPaletteOpen(true)} title="Command palette (⌘K)">
          <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
            <circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="M11 11l3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
          <span className="lbl">Jump to account, node, action…</span>
          <kbd>⌘K</kbd>
        </button>
        <button type="button" className="cx-iconbtn" onClick={toggle} title="Toggle theme (t)" aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
          <svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true">
            <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M8 1.8 A6.2 6.2 0 0 1 8 14.2 Z" fill="currentColor" />
          </svg>
        </button>
      </header>
      <Side current={section} />
      <main className="cx-main" id="cx-main">
        {live.stale && (
          <div className="cx-stalebar" role="status">
            <b>◌ Not updating.</b>
            <span>
              {live.lastOkAt ? (
                <>
                  Showing the cluster as of <span className="mono">{clock(live.lastOkAt)}</span>.{' '}
                </>
              ) : (
                'Nothing loaded yet. '
              )}
              The nodes keep serving; the console lost{' '}
              <span className="mono">{self?.node ?? location.host}</span>
              {live.staleError ? ` (${live.staleError})` : ''}. Retrying every 2 s…
            </span>
          </div>
        )}
        <div className="cx-view" key={path}>
          {children}
        </div>
      </main>
      <nav className="cx-tabbar" aria-label="Sections">
        {TABBAR.map((id) => (
          <Link key={id} to={SECTION[id].path} className={section.id === id ? 'on' : undefined}>
            <span>{SECTION[id].icon}</span>
            {SECTION[id].short ?? SECTION[id].label}
          </Link>
        ))}
        <button type="button" onClick={() => setPaletteOpen(true)}>
          <span>
            <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
              <circle cx="3" cy="8" r="1.4" fill="currentColor" />
              <circle cx="8" cy="8" r="1.4" fill="currentColor" />
              <circle cx="13" cy="8" r="1.4" fill="currentColor" />
            </svg>
          </span>
          More
        </button>
      </nav>
      <Drawer />
      <Palette />
      {palOpen && <WarmAttention />}
      <DialogHost />
      <Toasts />
    </div>
  )
}
