import { useEffect, useRef, type ReactNode } from 'react'
import { Link, navigate } from '../../lib/router'
import { Empty, Kbd, Loading, PageHead } from './kit'
import { closePanel, fullPath, openPanel, usePanel } from './nav'
import { noteDetail } from './recent'
import { SECTION, type SectionId } from './sections'

// One renderer per kind of row (node, shard, event, account…), shown either in the slide-over
// or as a full page. A kind's `use` hook loads what it needs and returns the pieces; `mode`
// lets the full page open more sections or lay them out in two columns.

export type DetailMode = 'drawer' | 'page'
export type DetailView = {
  title: ReactNode
  chip?: ReactNode
  body: ReactNode
  /** Small print under the body: where the data comes from, which node answered. */
  foot?: ReactNode
  loading?: boolean
  /** Set when the thing is gone (a node left, an event scrolled out). */
  missing?: ReactNode
  /** The full page may grow past the usual reading width (wide tables). */
  wide?: boolean
}
export type DetailKind = {
  /** Eyebrow over the title: "Node", "Firehose event". */
  kind: string
  section: SectionId
  use: (id: string, mode: DetailMode) => DetailView
}

const registry = new Map<string, DetailKind>()
export function registerDetail(type: string, k: DetailKind) {
  registry.set(type, k)
}
export const detailKind = (type: string) => registry.get(type)
export const detailPath = (type: string, id: string) => {
  const k = registry.get(type)
  return k ? fullPath(SECTION[k.section].path, type, id) : undefined
}

/** Notes a detail for ⌘K's "Recent" once it has loaded, by the title it shows. */
function useNoteRecent<E extends HTMLElement>(type: string, id: string, k: DetailKind, v: DetailView) {
  const title = useRef<E>(null)
  const ready = !v.loading && !v.missing
  useEffect(() => {
    if (ready) noteDetail({ type, id, kind: k.kind, title: title.current?.textContent?.trim() || id })
  }, [type, id, ready, k.kind])
  return title
}

function Inner({ type, id, k }: { type: string; id: string; k: DetailKind }) {
  const v = k.use(id, 'drawer')
  const body = useRef<HTMLDivElement>(null)
  const title = useNoteRecent<HTMLHeadingElement>(type, id, k, v)
  useEffect(() => {
    body.current?.scrollTo(0, 0)
  }, [id])
  return (
    <>
      <header>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="kind">{k.kind}</div>
          <h2 id="cx-drawer-t" ref={title}>
            {v.title}
          </h2>
        </div>
        {v.chip}
        <button type="button" className="cx-btn sm" title="Open as a full page (o)" onClick={() => navigate(detailPath(type, id)!)}>
          Full page ↗
        </button>
        <button type="button" className="cx-iconbtn" aria-label="Close (esc)" onClick={closePanel}>
          ✕
        </button>
      </header>
      <div className="dbody" ref={body}>
        {v.missing ? <Empty title="Not available">{v.missing}</Empty> : v.loading ? <Loading /> : v.body}
      </div>
      <div className="dfoot">
        <span>{v.foot}</span>
        <span style={{ marginLeft: 'auto' }}>
          <Kbd k="o" /> full page · <Kbd k="esc" /> close
        </span>
      </div>
    </>
  )
}

/** The slide-over, driven by ?open=type:id. */
export function Drawer() {
  const p = usePanel()
  const k = p && registry.get(p.type)
  if (!p || !k) return null
  return (
    <aside className="cx-drawer" role="dialog" aria-modal="false" aria-labelledby="cx-drawer-t">
      <Inner key={p.type} type={p.type} id={p.id} k={k} />
    </aside>
  )
}

/** A detail as a page of its own (/admin/<section>/<type>/<id>). */
export function DetailPage({ type, id }: { type: string; id: string }) {
  const k = registry.get(type)!
  const v = k.use(id, 'page')
  const title = useNoteRecent<HTMLSpanElement>(type, id, k, v)
  const sec = SECTION[k.section]
  return (
    <div className={`cx-fullpage${v.wide ? ' wide' : ''}`}>
      <PageHead
        title={
          <>
            <span ref={title}>{v.title}</span> {v.chip}
          </>
        }
        sub={
          <>
            <span className="cx-eyebrow">{k.kind}</span>
            {v.foot && <span>{v.foot}</span>}
          </>
        }
        actions={
          <>
            <Link className="cx-btn" to={sec.path}>
              ← {sec.label}
            </Link>
            <button
              type="button"
              className="cx-btn"
              onClick={() => {
                navigate(sec.path)
                openPanel(type, id)
              }}
            >
              Open as panel
            </button>
          </>
        }
      />
      <div className="cx-stack">{v.missing ? <Empty title="Not available">{v.missing}</Empty> : v.loading ? <Loading /> : v.body}</div>
    </div>
  )
}
