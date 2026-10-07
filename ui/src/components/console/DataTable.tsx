import { useMemo, useState, type CSSProperties, type ReactNode } from 'react'
import { Empty } from './kit'
import { openPanel, panelParam, usePanel, type PanelRef } from './nav'

// The console's table: dense rows, sortable columns, and rows that open in the slide-over.
// Rows with `open` carry data-open="type:id", which is all the shell's j/k/Enter handling needs.

export type Col<T> = {
  id: string
  label: ReactNode
  title?: string
  /** Right-aligned (numbers). */
  r?: boolean
  /** Makes the header clickable; descending first. */
  sort?: (a: T, b: T) => number
  render: (row: T) => ReactNode
  className?: string
  style?: CSSProperties
}

export function DataTable<T>({
  rows,
  cols,
  rowKey,
  open,
  onRow,
  sort: initial,
  compact,
  empty,
  dim,
  label,
}: {
  rows: T[]
  cols: Col<T>[]
  rowKey: (row: T) => string
  /** The detail a row opens in the slide-over. */
  open?: (row: T) => PanelRef | undefined
  /** Instead of `open`: a click handler (filters, focus). */
  onRow?: (row: T) => void
  sort?: { id: string; asc?: boolean }
  compact?: boolean
  empty?: ReactNode
  dim?: (row: T) => boolean
  label?: string
}) {
  const [sort, setSort] = useState(initial)
  const panel = usePanel()
  const sorted = useMemo(() => {
    const c = sort && cols.find((x) => x.id === sort.id)
    if (!c?.sort) return rows
    const s = [...rows].sort(c.sort)
    return sort?.asc ? s : s.reverse()
  }, [rows, cols, sort])
  return (
    <div className="cx-tw">
      <table className={`cx-t${compact ? ' compact' : ''}`} aria-label={label}>
        <thead>
          <tr>
            {cols.map((c) => {
              const on = sort?.id === c.id
              return (
                <th
                  key={c.id}
                  className={`${c.r ? 'r ' : ''}${c.sort ? 'sortable' : ''}`}
                  title={c.title}
                  aria-sort={on ? (sort?.asc ? 'ascending' : 'descending') : undefined}
                  onClick={c.sort ? () => setSort(on ? { id: c.id, asc: !sort?.asc } : { id: c.id }) : undefined}
                >
                  {c.label}
                  {on && (sort?.asc ? ' ↑' : ' ↓')}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td colSpan={cols.length}>{empty ?? <Empty>Nothing here.</Empty>}</td>
            </tr>
          )}
          {sorted.map((r) => {
            const o = open?.(r)
            const sel = o && panel && panel.type === o.type && panel.id === o.id
            return (
              <tr
                key={rowKey(r)}
                data-open={o ? panelParam(o.type, o.id) : onRow ? `row:${rowKey(r)}` : undefined}
                className={`${sel ? 'sel' : ''}${dim?.(r) ? ' dim' : ''}`}
                onClick={(e) => {
                  if ((e.target as HTMLElement).closest('button,a,input,select,textarea,label')) return
                  if (o) openPanel(o.type, o.id)
                  else onRow?.(r)
                }}
              >
                {cols.map((c) => (
                  <td key={c.id} className={`${c.r ? 'r ' : ''}${c.className ?? ''}`} style={c.style}>
                    {c.render(r)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
