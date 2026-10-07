import type { ReactNode } from 'react'

/** An older console page shown inside the new shell, in its own look, until its section is rebuilt. */
export function Legacy({ children }: { children: ReactNode }) {
  return <div className="cx-legacy">{children}</div>
}
