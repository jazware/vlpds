import { useEffect, useMemo, useRef, useState, type MouseEvent, type RefObject } from 'react'
import { loaders, nav, pages, type DocMeta } from 'virtual:vlpds-docs'
import { Topbar } from '../../components/ui'
import { Link, navigate } from '../../lib/router'
import '../../docs.css'
import { Lightbox, diagramOf, type Diagram } from './Lightbox'

const bySlug = new Map(pages.map((p) => [p.slug, p]))
const order = nav.flatMap((s) => s.pages)
const html = new Map<string, string>()

function slugOf(path: string): string {
  const s = path.replace(/^\/docs\/?/, '').replace(/\/+$/, '')
  return s || 'overview'
}

export function DocsApp({ path }: { path: string }) {
  const slug = slugOf(path)
  const page = bySlug.get(slug)
  const [body, setBody] = useState<string | null>(() => html.get(slug) ?? null)
  const [failed, setFailed] = useState(false)
  const [navOpen, setNavOpen] = useState(false)
  const [diagram, setDiagram] = useState<Diagram | null>(null)
  const article = useRef<HTMLDivElement>(null)

  useEffect(() => {
    document.title = page ? `${page.title} · vlpds docs` : 'Not found · vlpds docs'
    setNavOpen(false)
    setDiagram(null)
    setFailed(false)
    if (!page) return
    const cached = html.get(slug)
    setBody(cached ?? null)
    if (cached !== undefined) return
    let live = true
    loaders[slug]()
      .then((m) => {
        html.set(slug, m.default)
        if (live) setBody(m.default)
      })
      .catch(() => live && setFailed(true))
    return () => {
      live = false
    }
  }, [slug, page])

  // A deep link's anchor only exists once the page's HTML is in.
  useEffect(() => {
    if (body === null || !location.hash) return
    document.getElementById(decodeURIComponent(location.hash.slice(1)))?.scrollIntoView()
  }, [body])

  const onClick = (e: MouseEvent<HTMLDivElement>) => {
    const t = e.target as Element
    const fig = t.closest<HTMLElement>('.figure')
    if (fig && (t.closest('.dg-expand') || t.closest('svg.dg'))) {
      const d = diagramOf(fig)
      if (d) setDiagram(d)
      return
    }
    const a = t.closest('a')
    const href = a?.getAttribute('href')
    if (!a || !href || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    if (href.startsWith('/docs')) {
      e.preventDefault()
      const [p, hash] = href.split('#')
      if (p === location.pathname && hash) {
        history.pushState(null, '', `#${hash}`)
        document.getElementById(hash)?.scrollIntoView({ behavior: 'smooth' })
      } else navigate(href)
    }
  }

  const i = order.indexOf(slug)
  const prev = i > 0 ? bySlug.get(order[i - 1]) : undefined
  const next = i >= 0 && i < order.length - 1 ? bySlug.get(order[i + 1]) : undefined

  return (
    <>
      <Topbar where="docs" own />
      <div className="docs">
        <aside className={`docs-nav${navOpen ? ' open' : ''}`} aria-label="Documentation">
          <button className="docs-nav-toggle btn sm" aria-expanded={navOpen} onClick={() => setNavOpen((o) => !o)}>
            {page ? page.title : 'Contents'} <span aria-hidden="true">{navOpen ? '▴' : '▾'}</span>
          </button>
          <nav>
            {nav.map((s) => (
              <div key={s.name} className="docs-nav-sec">
                <h2>{s.name}</h2>
                {s.pages.map((p) => {
                  const m = bySlug.get(p)!
                  return (
                    <Link key={p} to={`/docs/${p}`} className={p.includes('/') ? 'sub' : undefined} aria-current={p === slug ? 'page' : undefined}>
                      {m.title}
                      {m.status === 'stub' && <span className="dot" title="Not written yet" />}
                    </Link>
                  )
                })}
              </div>
            ))}
          </nav>
        </aside>
        <main className="docs-main">
          {!page ? (
            <article className="doc">
              <h1>Page not found</h1>
              <p className="muted">
                There is no <code>{path}</code>. Start at the <Link to="/docs/overview">overview</Link>.
              </p>
            </article>
          ) : (
            <article className="doc">
              <header className="doc-head">
                <div className="crumbs">
                  <Link to="/docs">Docs</Link>
                  <span aria-hidden="true">/</span>
                  <span>{page.section}</span>
                  {page.status !== 'ready' && <span className={`badge badge-${page.status}`}>{page.status === 'stub' ? 'Outline' : 'Draft'}</span>}
                </div>
                <h1>{page.title}</h1>
                <p className="doc-summary">{page.summary}</p>
              </header>
              {failed ? (
                <p className="notice err">This page didn't load. Reload to try again.</p>
              ) : body === null ? (
                <div className="doc-loading" aria-busy="true" />
              ) : (
                <div className="doc-body" ref={article} onClick={onClick} dangerouslySetInnerHTML={{ __html: body }} />
              )}
              <PrevNext prev={prev} next={next} />
            </article>
          )}
        </main>
        {page && body !== null && <Toc page={page} root={article} />}
      </div>
      {diagram && <Lightbox diagram={diagram} onClose={() => setDiagram(null)} />}
    </>
  )
}

function PrevNext({ prev, next }: { prev?: DocMeta; next?: DocMeta }) {
  return (
    <nav className="doc-pn" aria-label="Previous and next page">
      {prev ? (
        <Link to={`/docs/${prev.slug}`} className="prev">
          <span>Previous</span>
          {prev.title}
        </Link>
      ) : (
        <span />
      )}
      {next && (
        <Link to={`/docs/${next.slug}`} className="next">
          <span>Next</span>
          {next.title}
        </Link>
      )}
    </nav>
  )
}

/** "On this page", highlighting the section being read. */
function Toc({ page, root }: { page: DocMeta; root: RefObject<HTMLDivElement | null> }) {
  const [active, setActive] = useState<string | null>(null)
  const items = useMemo(() => page.headings.filter((h) => h.level === 2), [page])
  useEffect(() => {
    const el = root.current
    if (!el) return
    const hs = items.map((h) => document.getElementById(h.id)).filter((x): x is HTMLElement => !!x)
    const onScroll = () => {
      let cur: string | null = null
      for (const h of hs) if (h.getBoundingClientRect().top < 120) cur = h.id
      setActive(cur)
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [root, items])
  if (items.length < 2) return <div className="docs-toc" />
  return (
    <nav className="docs-toc" aria-label="On this page">
      <h2>On this page</h2>
      {items.map((h) => (
        <a key={h.id} href={`#${h.id}`} aria-current={active === h.id ? 'true' : undefined}>
          {h.text}
        </a>
      ))}
    </nav>
  )
}
