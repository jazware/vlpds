import { useSyncExternalStore } from 'react'

// toast("Copied") from anywhere; the shell renders them bottom-centre for a few seconds.

type T = { id: number; msg: string; err?: boolean }
let items: T[] = []
let n = 0
const subs = new Set<() => void>()
const emit = () => subs.forEach((l) => l())

export function toast(msg: string, opts: { err?: boolean; ms?: number } = {}) {
  const id = ++n
  items = [...items.slice(-2), { id, msg, err: opts.err }]
  emit()
  setTimeout(
    () => {
      items = items.filter((t) => t.id !== id)
      emit()
    },
    opts.ms ?? (opts.err ? 6000 : 3200),
  )
}

export function Toasts() {
  const list = useSyncExternalStore(
    (l) => {
      subs.add(l)
      return () => {
        subs.delete(l)
      }
    },
    () => items,
  )
  return (
    <div className="cx-toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} className={`cx-toast${t.err ? ' err' : ''}`}>
          {t.err && <span className="cx-g s-err">■</span>}
          {t.msg}
        </div>
      ))}
    </div>
  )
}
