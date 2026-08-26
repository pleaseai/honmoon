import { useSyncExternalStore } from 'react'
import { getApprovals } from './api'
import { Approvals } from './components/Approvals'
import { AuditLog } from './components/AuditLog'
import { Overview } from './components/Overview'
import { PolicyView } from './components/PolicyView'
import { usePolling } from './hooks'

const NAV = [
  { slug: '/', label: 'Overview' },
  { slug: '/audit', label: 'Audit Log' },
  { slug: '/policies', label: 'Policies' },
  { slug: '/approvals', label: 'Approvals' },
] as const

type Slug = (typeof NAV)[number]['slug']

/**
 * Hash routing, not the History API: the dashboard is served both by Cloudflare
 * Pages (the demo) and by `honmoon-mgmt`'s rust-embed handler, and a hash needs
 * no SPA rewrite rule under either. An unknown or malformed hash falls back to
 * Overview without rewriting the URL.
 */
function currentSlug(): Slug {
  const raw = window.location.hash.replace(/^#/, '') || '/'
  return NAV.some(n => n.slug === raw) ? (raw as Slug) : '/'
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener('hashchange', onChange)
  return () => window.removeEventListener('hashchange', onChange)
}

function App() {
  // `currentSlug` returns a primitive, so the snapshot is stable by value.
  const slug = useSyncExternalStore(subscribe, currentSlug)
  // A live pending count drives the sidebar badge across every view.
  const { data: approvals } = usePolling(getApprovals, 1500)
  const pending = approvals?.length ?? 0

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
      <header className="border-b border-zinc-200 px-6 py-4 dark:border-zinc-800">
        <h1 className="text-lg font-semibold">
          Honmoon
          {' '}
          <span className="text-zinc-400">dashboard</span>
        </h1>
      </header>

      <div className="flex">
        <nav className="w-48 shrink-0 border-r border-zinc-200 p-4 dark:border-zinc-800">
          <ul className="space-y-1 text-sm">
            {NAV.map(item => (
              <li key={item.slug}>
                <a
                  href={`#${item.slug}`}
                  aria-current={slug === item.slug ? 'page' : undefined}
                  className={`flex w-full items-center justify-between rounded px-3 py-2 text-left ${
                    slug === item.slug
                      ? 'bg-zinc-200 font-medium dark:bg-zinc-800'
                      : 'hover:bg-zinc-100 dark:hover:bg-zinc-900'
                  }`}
                >
                  {item.label}
                  {item.slug === '/approvals' && pending > 0 && (
                    <span className="ml-2 rounded-full bg-amber-500 px-1.5 text-xs font-semibold text-white">
                      {pending}
                    </span>
                  )}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <main className="flex-1 p-6">
          {slug === '/' && <Overview />}
          {slug === '/audit' && <AuditLog />}
          {slug === '/policies' && <PolicyView />}
          {slug === '/approvals' && <Approvals />}
        </main>
      </div>
    </div>
  )
}

export default App
