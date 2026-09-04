import { useSyncExternalStore } from 'react'
import { getApprovals, getAudit } from './api'
import { Approvals } from './components/Approvals'
import { AuditLog } from './components/AuditLog'
import { Overview } from './components/Overview'
import { PolicyView } from './components/PolicyView'
import { usePolling } from './hooks'

const NAV = [
  { slug: '/', label: 'Overview' },
  { slug: '/audit', label: 'Audit' },
  { slug: '/policies', label: 'Policies' },
  { slug: '/approvals', label: 'Approvals' },
] as const

type Slug = (typeof NAV)[number]['slug']

/** Smallest audit read that still proves the endpoint answers. */
const probeAudit = () => getAudit(1)

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
  // A live pending count drives the nav badge across every view. Reachability
  // in the capsule needs both live endpoints to answer: the audit route can
  // fail on its own, and a badge that only watched approvals would still read
  // "live" while the Audit page shows an error.
  const { data: approvals, error: approvalsError } = usePolling(getApprovals, 1500)
  const { data: audit, error: auditError } = usePolling(probeAudit, 2000)
  const pending = approvals?.length ?? 0
  const settled = (approvals !== null || approvalsError !== null)
    && (audit !== null || auditError !== null)
  const reachable = approvalsError === null && auditError === null

  return (
    <div className="min-h-screen bg-bg text-fg">
      {/*
        Below `md` the nav capsule cannot fit beside the wordmark, so the
        header grows and the capsule wraps onto its own full-width row; it
        also scrolls horizontally as a last resort so no route is ever pushed
        off-screen.
      */}
      <header className="relative z-10 h-[72px] bg-[color-mix(in_oklch,var(--bg)_88%,transparent)] px-10 shadow-[inset_0_-1px_0_var(--hair)] max-md:h-auto max-md:px-6 max-md:py-2">
        <div className="mx-auto flex h-full max-w-[1440px] items-center max-md:flex-wrap max-md:gap-y-1">
          <a
            href="#/"
            className="flex min-h-11 items-center gap-2.5 rounded-md font-mono text-base font-semibold tracking-[-0.02em] text-fg no-underline"
          >
            <span
              aria-hidden="true"
              className="relative size-[23px] rounded-[7px] bg-accent shadow-[0_0_18px_var(--accent-glow),inset_0_1px_1px_oklch(100%_0_0/0.65)] after:absolute after:inset-[7px] after:rounded-sm after:bg-bg after:opacity-75 after:content-['']"
            />
            honmoon
          </a>

          <div className="ml-auto flex items-center rounded-full bg-[var(--surface-glass)] p-1 shadow-[inset_0_1px_0_var(--hair),inset_0_0_0_1px_var(--hair),var(--shadow)] max-md:ml-0 max-md:w-full max-md:overflow-x-auto">
            <nav aria-label="Dashboard pages" className="flex gap-0.5 max-md:flex-1 max-md:justify-between">
              {NAV.map(item => (
                <a
                  key={item.slug}
                  href={`#${item.slug}`}
                  aria-current={slug === item.slug ? 'page' : undefined}
                  className={`flex min-h-11 items-center rounded-full px-[18px] text-xs font-medium tracking-[0.02em] no-underline transition-[background-color,color,transform] duration-500 ease-[var(--ease)] hover:-translate-y-px hover:text-fg motion-reduce:transition-none max-md:px-3 ${
                    slug === item.slug
                      ? 'bg-accent-soft text-fg shadow-[inset_0_0_0_1px_var(--accent-line)]'
                      : 'text-muted'
                  }`}
                >
                  {item.label}
                  {item.slug === '/approvals' && pending > 0 && (
                    <span className="count-badge">
                      {pending}
                      <span className="sr-only"> pending</span>
                    </span>
                  )}
                </a>
              ))}
            </nav>

            <GatewayState reachable={reachable} settled={settled} />

            <span
              role="img"
              aria-label="Account"
              className="mr-0.5 grid size-9 shrink-0 place-items-center rounded-full bg-[var(--surface-soft)] text-muted shadow-[inset_0_0_0_1px_var(--hair)] max-md:hidden"
            >
              <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <circle cx="8" cy="5.5" r="3" stroke="currentColor" strokeWidth="1.4" />
                <path d="M2.5 14c.6-3 3-4.5 5.5-4.5s4.9 1.5 5.5 4.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
              </svg>
            </span>
          </div>
        </div>
      </header>

      <main>
        {slug === '/' && <Overview />}
        {slug === '/audit' && <AuditLog />}
        {slug === '/policies' && <PolicyView />}
        {slug === '/approvals' && <Approvals />}
      </main>
    </div>
  )
}

/**
 * Live management-API reachability, derived from the approvals and audit
 * polls. It says whether the API answers — nothing about what the gateway
 * enforces.
 */
function GatewayState({ reachable, settled }: { reachable: boolean, settled: boolean }) {
  const label = !settled ? 'Connecting' : reachable ? 'Gateway live' : 'Gateway unreachable'
  const dot = !settled
    ? 'bg-muted'
    : reachable
      ? 'bg-accent shadow-[0_0_11px_var(--accent-glow)]'
      : 'bg-deny'
  return (
    <span
      role="status"
      className="ml-1.5 flex min-h-11 items-center gap-2 px-3 font-mono text-[9px] font-medium tracking-[0.1em] text-muted uppercase max-md:hidden"
    >
      <i aria-hidden="true" className={`size-[7px] rounded-full ${dot}`} />
      {label}
    </span>
  )
}

export default App
