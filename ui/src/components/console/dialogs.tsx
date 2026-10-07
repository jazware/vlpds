import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { errText } from '../../lib/xrpc'
import { Spinner } from './kit'
import { toast } from './toast'

// One modal at a time, opened imperatively: confirmAction() for anything that changes the
// cluster (typed confirm, consequences, the exact call it makes), openDialog() for forms.

type Render = (close: () => void) => ReactNode
let current: { id: number; render: Render } | null = null
let n = 0
const subs = new Set<() => void>()
const emit = () => subs.forEach((l) => l())

export function openDialog(render: Render) {
  current = { id: ++n, render }
  emit()
}
export function closeDialog() {
  current = null
  emit()
}
export const isDialogOpen = () => current !== null

export function DialogHost() {
  const d = useSyncExternalStore(
    (l) => {
      subs.add(l)
      return () => {
        subs.delete(l)
      }
    },
    () => current,
  )
  if (!d) return null
  return (
    <div
      className="cx-scrim"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) closeDialog()
      }}
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation()
          closeDialog()
        }
      }}
    >
      <div key={d.id} style={{ display: 'contents' }}>
        {d.render(closeDialog)}
      </div>
    </div>
  )
}

export type Field = { id: string; label: string; placeholder?: string; required?: boolean; type?: 'text' | 'checkbox' | 'textarea' | 'number'; initial?: string }

export type ConfirmSpec = {
  tone: 'err' | 'warn'
  title: string
  /** What will happen, one consequence per item. */
  items: ReactNode[]
  fields?: Field[]
  /** Must be typed exactly to enable the button (a handle, a node id, "off"). */
  word?: string
  action: string
  /** A reversible or routine action: verdigris button instead of red. */
  primary?: boolean
  /** The request it sends, shown in the footer: "vlpds.admin.setFeatureLevel {level: 8}". */
  call: string
  run: (values: Record<string, string | boolean>) => Promise<unknown>
  done?: string | ((result: unknown) => string)
}

/** Resolves true once `run` succeeded, false if cancelled. Errors stay in the dialog. */
export function confirmAction(spec: ConfirmSpec): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false
    const finish = (v: boolean) => {
      if (settled) return
      settled = true
      resolve(v)
    }
    openDialog((close) => (
      <ConfirmDialog
        spec={spec}
        onCancel={() => {
          close()
          finish(false)
        }}
        onDone={() => {
          // before close(): closing settles the promise as cancelled
          finish(true)
          close()
        }}
      />
    ))
    const unsub = () => {
      if (!current) {
        finish(false)
        subs.delete(unsub)
      }
    }
    subs.add(unsub)
  })
}

function ConfirmDialog({ spec, onCancel, onDone }: { spec: ConfirmSpec; onCancel: () => void; onDone: () => void }) {
  const [vals, setVals] = useState<Record<string, string | boolean>>(() => Object.fromEntries((spec.fields ?? []).map((f) => [f.id, f.type === 'checkbox' ? false : (f.initial ?? '')])))
  const [word, setWord] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()
  const first = useRef<HTMLInputElement | HTMLTextAreaElement | null>(null)
  useEffect(() => {
    setTimeout(() => first.current?.focus(), 20)
  }, [])
  const okWord = !spec.word || word.trim() === spec.word
  const okReq = (spec.fields ?? []).every((f) => !f.required || String(vals[f.id] ?? '').trim())
  const can = okWord && okReq && !busy
  const go = async () => {
    if (!can) return
    setBusy(true)
    setError(undefined)
    try {
      const r = await spec.run(vals)
      const msg = typeof spec.done === 'function' ? spec.done(r) : spec.done
      if (msg) toast(msg)
      onDone()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  let firstSet = false
  const ref = (el: HTMLInputElement | HTMLTextAreaElement | null) => {
    if (!firstSet && el) {
      first.current = el
      firstSet = true
    }
  }
  return (
    <form
      className="cx-dlg"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="cx-dlg-t"
      onSubmit={(e) => {
        e.preventDefault()
        go()
      }}
    >
      <div className="dh">
        <div className={`ico ${spec.tone}`} aria-hidden="true">
          {spec.tone === 'err' ? '■' : '▲'}
        </div>
        <h2 id="cx-dlg-t">{spec.title}</h2>
      </div>
      <div className="db">
        <ul>
          {spec.items.map((x, i) => (
            <li key={i}>{x}</li>
          ))}
        </ul>
        {(spec.fields ?? []).map((f) =>
          f.type === 'checkbox' ? (
            <label key={f.id} className="cx-form-row" style={{ gap: 8, cursor: 'pointer' }}>
              <input type="checkbox" checked={!!vals[f.id]} onChange={(e) => setVals((v) => ({ ...v, [f.id]: e.target.checked }))} /> {f.label}
            </label>
          ) : (
            <div key={f.id}>
              <label className="cx-lbl" htmlFor={`cf_${f.id}`}>
                {f.label}
              </label>
              {f.type === 'textarea' ? (
                <textarea ref={ref} id={`cf_${f.id}`} className="cx-inp" rows={2} placeholder={f.placeholder} value={String(vals[f.id] ?? '')} onChange={(e) => setVals((v) => ({ ...v, [f.id]: e.target.value }))} />
              ) : (
                <input
                  ref={ref}
                  id={`cf_${f.id}`}
                  className="cx-inp"
                  type={f.type === 'number' ? 'number' : 'text'}
                  placeholder={f.placeholder}
                  autoComplete="off"
                  value={String(vals[f.id] ?? '')}
                  onChange={(e) => setVals((v) => ({ ...v, [f.id]: e.target.value }))}
                />
              )}
            </div>
          ),
        )}
        {spec.word && (
          <div>
            <label className="cx-lbl" htmlFor="cf_word">
              Type{' '}
              <b className="mono" style={{ color: 'var(--ink)' }}>
                {spec.word}
              </b>{' '}
              to confirm
            </label>
            <input ref={ref} id="cf_word" className="cx-inp mono" autoComplete="off" spellCheck={false} value={word} onChange={(e) => setWord(e.target.value)} />
          </div>
        )}
        {!!error && (
          <div className="dlg-err" role="alert">
            <span className="cx-g">■</span>
            <span>{errText(error)}</span>
          </div>
        )}
      </div>
      <div className="df">
        <span className="call" title={spec.call}>
          {spec.call}
        </span>
        <button type="button" className="cx-btn" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className={`cx-btn ${spec.primary ? 'primary' : 'solid-danger'}`} disabled={!can}>
          {busy && <Spinner />}
          {spec.action}
        </button>
      </div>
    </form>
  )
}

/** The frame for a form dialog: icon, title, body, a footer with the call and buttons. */
export function FormDialog({
  title,
  icon = '+',
  children,
  call,
  action,
  busy,
  disabled,
  error,
  onSubmit,
  onCancel,
}: {
  title: string
  icon?: ReactNode
  children: ReactNode
  call?: string
  action: string
  busy?: boolean
  disabled?: boolean
  error?: unknown
  onSubmit: () => void
  onCancel: () => void
}) {
  return (
    <form
      className="cx-dlg"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cx-dlg-t"
      onSubmit={(e) => {
        e.preventDefault()
        if (!busy && !disabled) onSubmit()
      }}
    >
      <div className="dh">
        <div className="ico acc" aria-hidden="true">
          {icon}
        </div>
        <h2 id="cx-dlg-t">{title}</h2>
      </div>
      <div className="db">
        {children}
        {!!error && (
          <div className="dlg-err" role="alert">
            <span className="cx-g">■</span>
            <span>{errText(error)}</span>
          </div>
        )}
      </div>
      <div className="df">
        <span className="call" title={call}>
          {call}
        </span>
        <button type="button" className="cx-btn" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="cx-btn primary" disabled={busy || disabled}>
          {busy && <Spinner />}
          {action}
        </button>
      </div>
    </form>
  )
}
