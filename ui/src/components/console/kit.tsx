import { useState, type CSSProperties, type ReactNode } from 'react'
import { useLiveState } from '../../lib/console/live'
import { Link } from '../../lib/router'
import { errText } from '../../lib/xrpc'
import { toast } from './toast'

// The console's small parts. Everything here is presentational: data comes in as props.
// Status always pairs a colour with a glyph (● ok, ▲ warn, ■ err, ◆ info, ○ idle) so it reads
// without colour too.

export type Tone = 'ok' | 'warn' | 'err' | 'info' | 'idle'
export const GLYPH: Record<Tone, string> = { ok: '●', warn: '▲', err: '■', info: '◆', idle: '○' }

export function Glyph({ k, title }: { k: Tone; title?: string }) {
  return (
    <span className={`cx-g s-${k}`} title={title} aria-hidden={title ? undefined : true}>
      {GLYPH[k]}
    </span>
  )
}

export type ChipKind = Tone | 'acc' | 'plain' | 'violet' | 'stale'
/** A short status word. Tones get their glyph; `acc`, `plain`, `violet` are labels. */
export function Chip({ k, children, title, glyph = true }: { k: ChipKind; children: ReactNode; title?: string; glyph?: boolean }) {
  const g = glyph && k in GLYPH ? GLYPH[k as Tone] : undefined
  return (
    <span className={`cx-chip ${k}`} title={title}>
      {g && <span className="cx-g">{g}</span>}
      {children}
    </span>
  )
}

export function Kbd({ k }: { k: string | string[] }) {
  const keys = Array.isArray(k) ? k : [k]
  return (
    <>
      {keys.map((x, i) => (
        <span key={i}>
          {i > 0 && ' '}
          <kbd>{x}</kbd>
        </span>
      ))}
    </>
  )
}

/** A node's colour square; striped red when nobody owns the thing. */
export function Swatch({ color, title }: { color?: string; title?: string }) {
  return <span className={`cx-sw${color ? '' : ' none'}`} style={color ? { background: color } : undefined} title={title} />
}

/** Wraps a value that updates live: hatched while the console is stale. */
export function LiveVal({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={`cx-live${className ? ` ${className}` : ''}`}>{children}</span>
}

// ---------------------------------------------------------------- sparklines, meters

function sparkPath(arr: (number | null)[], max: number, h: number): string {
  const n = arr.length
  let d = ''
  let pen = false
  for (let i = 0; i < n; i++) {
    const v = arr[i]
    if (v == null || !isFinite(v)) {
      pen = false
      continue
    }
    const x = n > 1 ? (i * 100) / (n - 1) : 0
    const y = h - 1.5 - (v / max) * (h - 4)
    d += `${pen ? 'L' : 'M'}${x.toFixed(2)} ${y.toFixed(2)}`
    pen = true
  }
  return d
}

/**
 * A sparkline in a 100-wide box that stretches to its container. `color` and `color2` are
 * token names (accent, amber, c1…, warn). `l2` draws dashed on the same scale, `th` a dotted
 * threshold. Fewer than two points draws a hatched placeholder.
 */
export function Spark({
  data,
  l2,
  color = 'accent',
  color2 = 'ink3',
  th,
  min,
  size,
  title,
}: {
  data: (number | null | undefined)[]
  l2?: (number | null | undefined)[]
  color?: string
  color2?: string
  th?: number
  min?: number
  size?: 'inline' | 'big'
  title?: string
}) {
  const h = size === 'big' ? 64 : 26
  const a = data.map((v) => v ?? null)
  const b = l2?.map((v) => v ?? null)
  const vals = [...a, ...(b ?? [])].filter((v): v is number => v != null && isFinite(v))
  const cls = `cx-spark${size ? ` ${size}` : ''}`
  if (a.filter((v) => v != null).length < 2) return <svg className={`${cls} empty`} viewBox={`0 0 100 ${h}`} aria-hidden="true" />
  const max = Math.max(...vals, (th ?? 0) * 1.05, min ?? 0) * 1.12 || 1
  const d = sparkPath(a, max, h)
  const firstX = d.match(/^M([\d.]+)/)?.[1] ?? '0'
  const lastX = d.match(/([\d.]+) [\d.]+$/)?.[1] ?? '100'
  const thy = th ? (h - 1.5 - (th / max) * (h - 4)).toFixed(2) : undefined
  return (
    <svg className={cls} viewBox={`0 0 100 ${h}`} preserveAspectRatio="none" aria-hidden={title ? undefined : true} role={title ? 'img' : undefined} aria-label={title}>
      <path className="a" d={`${d}L${lastX} ${h}L${firstX} ${h}Z`} fill={`color-mix(in oklab, var(--${color}) 15%, transparent)`} />
      {thy && <line className="th" x1="0" x2="100" y1={thy} y2={thy} />}
      {b && <path className="l2" d={sparkPath(b, max, h)} stroke={`var(--${color2})`} />}
      <path className="l" d={d} stroke={`var(--${color})`} />
    </svg>
  )
}

export function Meter({ v, max, k, wide, title }: { v: number; max: number; k?: 'ok' | 'warn' | 'err' | 'info'; wide?: boolean; title?: string }) {
  const pct = max > 0 ? Math.min(100, Math.max(0, (v / max) * 100)) : 0
  return (
    <span className={`cx-meter${k ? ` ${k}` : ''}${wide ? ' wide' : ''}`} title={title} role="meter" aria-valuenow={v} aria-valuemax={max}>
      <i style={{ width: `${pct.toFixed(1)}%` }} />
    </span>
  )
}

export function MiniBar({ parts, width = 56 }: { parts: { v: number; color: string; title?: string }[]; width?: number }) {
  const total = parts.reduce((a, p) => a + p.v, 0) || 1
  return (
    <span className="cx-minibar" style={{ width }}>
      {parts.map((p, i) => (
        <i key={i} style={{ width: `${(p.v / total) * 100}%`, background: p.color }} title={p.title} />
      ))}
    </span>
  )
}

// ---------------------------------------------------------------- tiles, health line

export type TileSpec = {
  label: ReactNode
  right?: ReactNode
  value: ReactNode
  unit?: ReactNode
  sec?: ReactNode
  spark?: ReactNode
  to?: string
  title?: string
}
export function Tiles({ tiles, boxed }: { tiles: TileSpec[]; boxed?: boolean }) {
  const t = (
    <div className="cx-tiles">
      {tiles.map((x, i) => {
        const inner = (
          <>
            <div className="tl">
              <span>{x.label}</span>
              {x.right && <span className="muted">{x.right}</span>}
            </div>
            <div className="tv">
              <LiveVal>{x.value}</LiveVal>
              {x.unit && <small>{x.unit}</small>}
              {x.sec && <span className="sec">{x.sec}</span>}
            </div>
            {x.spark}
          </>
        )
        return x.to ? (
          <Link key={i} to={x.to} className="cx-tile" title={x.title}>
            {inner}
          </Link>
        ) : (
          <div key={i} className="cx-tile" title={x.title}>
            {inner}
          </div>
        )
      })}
    </div>
  )
  return boxed ? <div className="cx-tilesbox">{t}</div> : t
}

export type HealthCell = { label: string; tone: Tone; value: ReactNode; unit?: ReactNode; sub: ReactNode; to: string; title?: string }
/** One line of cells, one per subsystem; a warn or err cell gets a top rule. */
export function HealthLine({ cells }: { cells: HealthCell[] }) {
  return (
    <div className="cx-health" role="list" aria-label="Health">
      {cells.map((c) => (
        <Link key={c.label} to={c.to} className={`cx-hc${c.tone === 'warn' || c.tone === 'err' ? ` ${c.tone}` : ''}`} role="listitem" title={c.title}>
          <span className="hl">
            <Glyph k={c.tone} />
            {c.label}
          </span>
          <span className="hv">
            <LiveVal>{c.value}</LiveVal>
            {c.unit && <small> {c.unit}</small>}
          </span>
          <span className="hs">{c.sub}</span>
        </Link>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------- banners

export type BannerSpec = { id: string; tone: Tone; title: ReactNode; desc?: ReactNode; right?: ReactNode; body?: ReactNode; open?: boolean }
/** Collapsible notices across the top of a page; `body` is what opens. */
export function Banners({ items }: { items: BannerSpec[] }) {
  if (!items.length) return null
  return (
    <div className="cx-banners">
      {items.map((b) =>
        b.body ? (
          <details key={b.id} className={`cx-banner ${b.tone}`} open={b.open}>
            <summary>
              <Glyph k={b.tone} />
              <span className="bt">{b.title}</span>
              {b.desc && <span className="bd">{b.desc}</span>}
              <span className="bx">
                {b.right}
                <span className="cx-chev">›</span>
              </span>
            </summary>
            <div className="bb">{b.body}</div>
          </details>
        ) : (
          <div key={b.id} className={`cx-banner ${b.tone}`}>
            <div className="bh">
              <Glyph k={b.tone} />
              <span className="bt">{b.title}</span>
              {b.desc && <span className="bd">{b.desc}</span>}
              {b.right && <span className="bx">{b.right}</span>}
            </div>
          </div>
        ),
      )}
    </div>
  )
}

// ---------------------------------------------------------------- panels, sections, page head

/** Where a panel's data comes from; hidden unless the "Show data sources" toggle is on. */
export function Src({ children, isNew }: { children: ReactNode; isNew?: boolean }) {
  const { showSources } = useLiveState()
  if (!showSources) return null
  return (
    <span className={`cx-src${isNew ? ' new' : ''}`} title={isNew ? 'Needs an endpoint newer vlpds builds add' : 'Where this panel reads from'}>
      {isNew ? 'new · ' : ''}
      {children}
    </span>
  )
}

export function Panel({
  title,
  to,
  src,
  right,
  foot,
  children,
  id,
  className,
  style,
}: {
  title?: ReactNode
  /** Section path the title links to (shown with a ›). */
  to?: string
  src?: ReactNode
  right?: ReactNode
  foot?: ReactNode
  children?: ReactNode
  id?: string
  className?: string
  style?: CSSProperties
}) {
  return (
    <section className={`cx-pn${className ? ` ${className}` : ''}`} id={id} style={style}>
      {(title || right) && (
        <div className="cx-pn-h">
          {title && <h3>{to ? <Link to={to}>{title} ›</Link> : title}</h3>}
          {src}
          {right && <div className="r">{right}</div>}
        </div>
      )}
      {children}
      {foot && <div className="cx-pn-f">{foot}</div>}
    </section>
  )
}
/** Padding for free content inside a Panel (tables and tiles go flush). */
export const PanelBody = ({ children }: { children: ReactNode }) => <div className="cx-pn-b">{children}</div>

/** A collapsible section (drawers, detail pages). `flush` drops the body padding for tables. */
export function Sec({
  title,
  digest,
  right,
  open,
  flush,
  danger,
  children,
}: {
  title: ReactNode
  digest?: ReactNode
  right?: ReactNode
  open?: boolean
  flush?: boolean
  danger?: boolean
  children: ReactNode
}) {
  return (
    <details className={`cx-sec${danger ? ' danger' : ''}`} open={open}>
      <summary>
        <span className="cx-chev">›</span>
        {title}
        <span className="dg">{digest}</span>
        {right && <span className="r">{right}</span>}
      </summary>
      <div className={flush ? undefined : 'sb'}>{children}</div>
    </details>
  )
}

export function PageHead({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="cx-ph">
      <div style={{ minWidth: 0 }}>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {actions && <div className="acts">{actions}</div>}
    </div>
  )
}

/** A row's status chip and action, each in its own column so they line up down the list. */
export type KVExtra = { chip?: ReactNode; act?: ReactNode }
export type KVRow = [ReactNode, ReactNode] | [ReactNode, ReactNode, KVExtra]

export function KV({ rows, style }: { rows: KVRow[]; style?: CSSProperties }) {
  const x = rows.some((r) => r[2])
  return (
    <dl className={`cx-kv${x ? ' x' : ''}`} style={style}>
      {rows.map(([k, v, e], i) => (
        <div key={i} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
          {x && <dd className="kc">{e?.chip}</dd>}
          {x && <dd className="ka">{e?.act}</dd>}
        </div>
      ))}
    </dl>
  )
}

/** A row of figures across the top of a drawer. */
export function Strip({ items }: { items: [string, ReactNode][] }) {
  return (
    <div className="cx-strip">
      {items.map(([l, v]) => (
        <div key={l}>
          <b>
            <LiveVal>{v}</LiveVal>
          </b>
          <span>{l}</span>
        </div>
      ))}
    </div>
  )
}

/** One labelled sparkline in a grid of `Minis`. */
export function Mini({ label, value, children }: { label: ReactNode; value: ReactNode; children?: ReactNode }) {
  return (
    <div className="cx-mini">
      <div className="ml">
        <span>{label}</span>
        <b>
          <LiveVal>{value}</LiveVal>
        </b>
      </div>
      {children}
    </div>
  )
}
export const Minis = ({ n = 2, children, style }: { n?: number; children: ReactNode; style?: CSSProperties }) => (
  <div className="cx-minis" data-n={n} style={{ ['--n' as string]: n, ...style }}>
    {children}
  </div>
)

/** A compact list row (right rails, drawers): glyph, name, a right-aligned note. */
export function RRow({ onClick, to, children, x, title }: { onClick?: () => void; to?: string; children: ReactNode; x?: ReactNode; title?: string }) {
  const inner = (
    <>
      {children}
      {x !== undefined && <span className="x">{x}</span>}
    </>
  )
  if (to)
    return (
      <Link to={to} className="cx-rrow" title={title}>
        {inner}
      </Link>
    )
  if (onClick)
    return (
      <button type="button" className="cx-rrow" onClick={onClick} title={title}>
        {inner}
      </button>
    )
  return (
    <div className="cx-rrow" title={title}>
      {inner}
    </div>
  )
}

/** Click to copy (ids, DIDs, CIDs): the value itself is the button. */
export function Copy({ text, children, mono = true, full, className }: { text: string; children?: ReactNode; mono?: boolean; full?: boolean; className?: string }) {
  return (
    <button
      type="button"
      className={`cx-copy${mono ? ' mono' : ''}${className ? ` ${className}` : ''}`}
      title={full ? `${text}\nClick to copy` : 'Click to copy'}
      onClick={(e) => {
        e.stopPropagation()
        navigator.clipboard.writeText(text).then(
          () => toast(`Copied ${text.length > 48 ? `${text.slice(0, 48)}…` : text}`),
          () => toast('Select the text to copy it'),
        )
      }}
    >
      {children ?? text}
    </button>
  )
}

export function Spinner() {
  return <span className="cx-spin" role="status" aria-label="Loading" />
}

// ---------------------------------------------------------------- states

export function Empty({ title, children }: { title?: ReactNode; children?: ReactNode }) {
  return (
    <div className="cx-empty">
      {title && <b>{title}</b>}
      {children}
    </div>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="cx-empty">
      <Spinner /> {label}
    </div>
  )
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  return (
    <div className="cx-errbox" role="alert">
      <Glyph k="err" />
      <span className="msg">{errText(error)}</span>
      {retry && (
        <button type="button" className="cx-btn sm" onClick={retry}>
          Retry
        </button>
      )}
    </div>
  )
}

/** In place of a panel whose endpoint this server doesn't have yet. */
export function NeedsVersion({ what, nsid }: { what: ReactNode; nsid: string }) {
  return (
    <div className="cx-needs">
      <Glyph k="idle" />
      <span>
        <b>{what}</b> needs a newer vlpds: this server has no <span className="mono">{nsid}</span>.
      </span>
    </div>
  )
}

/** Loading / error / content for one load, keeping the last data while it refreshes. */
export function Loaded<T>({ load, children, empty }: { load: { data?: T; error?: unknown; loading: boolean; reload?: () => void }; children: (d: T) => ReactNode; empty?: ReactNode }) {
  if (load.data !== undefined) return <>{children(load.data)}</>
  if (load.error) return <ErrorState error={load.error} retry={load.reload} />
  if (load.loading) return <Loading />
  return <>{empty ?? null}</>
}

// ---------------------------------------------------------------- JSON

export function Json({ value }: { value: unknown }) {
  return <pre className="cx-json">{renderJson(value, 0)}</pre>
}
function renderJson(v: unknown, d: number): ReactNode {
  const pad = '  '.repeat(d + 1)
  const end = '  '.repeat(d)
  if (v === null || v === undefined) return <span className="b">{String(v)}</span>
  if (typeof v === 'boolean' || typeof v === 'number' || typeof v === 'bigint') return <span className="n">{String(v)}</span>
  if (typeof v === 'string') return <span className="s">{JSON.stringify(v)}</span>
  if (Array.isArray(v))
    return v.length ? (
      <>
        {'[\n'}
        {v.map((x, i) => (
          <span key={i}>
            {pad}
            {renderJson(x, d + 1)}
            {i < v.length - 1 ? ',\n' : '\n'}
          </span>
        ))}
        {end}]
      </>
    ) : (
      '[]'
    )
  const e = Object.entries(v as Record<string, unknown>)
  return e.length ? (
    <>
      {'{\n'}
      {e.map(([k, x], i) => (
        <span key={k}>
          {pad}
          <span className="k">{JSON.stringify(k)}</span>: {renderJson(x, d + 1)}
          {i < e.length - 1 ? ',\n' : '\n'}
        </span>
      ))}
      {end}
      {'}'}
    </>
  ) : (
    '{}'
  )
}

/** Toggle with its state in the label for screen readers. */
export function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return <button type="button" className={`cx-toggle${on ? ' on' : ''}`} aria-pressed={on} aria-label={label} onClick={() => onChange(!on)} />
}

/** A segmented control. */
export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: { v: T; label: ReactNode; n?: ReactNode }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="cx-seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.v} type="button" className={o.v === value ? 'on' : undefined} aria-pressed={o.v === value} onClick={() => onChange(o.v)}>
          {o.label}
          {o.n !== undefined && <span className="n">{o.n}</span>}
        </button>
      ))}
    </div>
  )
}

/** A text input that stays controlled locally (search boxes). `data-search` makes `/` focus it. */
export function SearchInput({ value, onChange, placeholder, mono, style }: { value: string; onChange: (v: string) => void; placeholder: string; mono?: boolean; style?: CSSProperties }) {
  const [v, setV] = useState(value)
  return (
    <input
      className={`cx-inp${mono ? ' mono' : ''}`}
      data-search
      value={v}
      placeholder={placeholder}
      aria-label={placeholder}
      spellCheck={false}
      autoComplete="off"
      style={style}
      onChange={(e) => {
        setV(e.target.value)
        onChange(e.target.value)
      }}
    />
  )
}
