import { useState } from 'react'
import { getApprovals } from './api'
import { Approvals } from './components/Approvals'
import { AuditLog } from './components/AuditLog'
import { Overview } from './components/Overview'
import { PolicyView } from './components/PolicyView'
import { usePolling } from './hooks'

const NAV = ['Overview', 'Audit Log', 'Policies', 'Approvals'] as const
type View = (typeof NAV)[number]

function App() {
  const [view, setView] = useState<View>('Overview')
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
              <li key={item}>
                <button
                  type="button"
                  onClick={() => setView(item)}
                  className={`flex w-full items-center justify-between rounded px-3 py-2 text-left ${
                    view === item
                      ? 'bg-zinc-200 font-medium dark:bg-zinc-800'
                      : 'hover:bg-zinc-100 dark:hover:bg-zinc-900'
                  }`}
                >
                  {item}
                  {item === 'Approvals' && pending > 0 && (
                    <span className="ml-2 rounded-full bg-amber-500 px-1.5 text-xs font-semibold text-white">
                      {pending}
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <main className="flex-1 p-6">
          {view === 'Overview' && <Overview onNavigate={v => setView(v as View)} />}
          {view === 'Audit Log' && <AuditLog />}
          {view === 'Policies' && <PolicyView />}
          {view === 'Approvals' && <Approvals />}
        </main>
      </div>
    </div>
  )
}

export default App
