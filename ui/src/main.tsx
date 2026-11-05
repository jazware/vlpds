import { StrictMode, Suspense, lazy, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'
import { brand } from './lib/brand'
import { usePath } from './lib/router'
import { Landing } from './pages/Landing'
import { AccountApp } from './pages/account/AccountApp'
import { Migrate } from './pages/migrate/Migrate'

// its own chunk: the nav and page index aren't needed anywhere else
const DocsApp = lazy(() => import('./pages/docs/DocsApp').then((m) => ({ default: m.DocsApp })))
// the operator console too: nobody else loads it
const AdminApp = lazy(() => import('./pages/admin/AdminApp').then((m) => ({ default: m.AdminApp })))

function App() {
  const path = usePath()
  const area = path.startsWith('/account')
    ? 'account'
    : path.startsWith('/admin')
      ? 'admin'
      : path.startsWith('/migrate')
        ? 'migrate'
        : path === '/docs' || path.startsWith('/docs/')
          ? 'docs'
          : 'landing'
  useEffect(() => {
    if (area === 'docs') return // DocsApp titles each page
    // the operator's name where the theme has one (the console stays vlpds's)
    const name = brand.name
    document.title =
      area === 'account' ? `Account · ${name}` : area === 'admin' ? 'Console · vlpds' : area === 'migrate' ? `Move here · ${name}` : brand.custom ? name : `${location.hostname} · vlpds`
  }, [area])
  if (area === 'landing') return <Landing />
  if (area === 'docs')
    return (
      <Suspense fallback={null}>
        <DocsApp path={path} />
      </Suspense>
    )
  if (area === 'admin')
    return (
      <Suspense fallback={null}>
        <AdminApp path={path} />
      </Suspense>
    )
  return area === 'account' ? <AccountApp path={path} /> : <Migrate />
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
