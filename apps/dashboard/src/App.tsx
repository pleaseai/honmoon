const NAV = ['Overview', 'Audit Log', 'Policies', 'Approvals'] as const

function App() {
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
              <li
                key={item}
                className="cursor-pointer rounded px-3 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-900"
              >
                {item}
              </li>
            ))}
          </ul>
        </nav>

        <main className="flex-1 p-6">
          <p className="text-sm text-zinc-500">
            Scaffold ready. Wire up audit log, policy editor, and approval queue here.
          </p>
        </main>
      </div>
    </div>
  )
}

export default App
