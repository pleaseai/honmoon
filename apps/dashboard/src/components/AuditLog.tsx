import { getAudit } from '../api'
import { describeFacts, formatTime } from '../format'
import { usePolling } from '../hooks'
import { DecisionBadge } from './DecisionBadge'

export function AuditLog() {
  const { data, error, loading } = usePolling(getAudit, 2000)
  const events = data ?? []

  return (
    <section>
      <header className="mb-4 flex items-baseline gap-3">
        <h2 className="text-base font-semibold">Audit log</h2>
        <span className="text-sm text-zinc-500">
          {events.length}
          {' '}
          recent events
        </span>
      </header>

      {error && (
        <p className="mb-3 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-300">
          {error}
        </p>
      )}

      {loading && events.length === 0
        ? <p className="text-sm text-zinc-500">Loading…</p>
        : events.length === 0
          ? <p className="text-sm text-zinc-500">No decisions recorded yet.</p>
          : (
              <div className="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800">
                <table className="w-full border-collapse text-sm">
                  <thead className="bg-zinc-100 text-left text-xs uppercase tracking-wide text-zinc-500 dark:bg-zinc-900">
                    <tr>
                      <th className="px-3 py-2 font-medium">Time</th>
                      <th className="px-3 py-2 font-medium">Decision</th>
                      <th className="px-3 py-2 font-medium">Request</th>
                      <th className="px-3 py-2 font-medium">Rule</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map(e => (
                      <tr
                        key={e.id}
                        className="border-t border-zinc-100 dark:border-zinc-800/70"
                      >
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-zinc-500">
                          {formatTime(e.timestamp)}
                        </td>
                        <td className="px-3 py-2">
                          <DecisionBadge decision={e.decision} />
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">
                          {describeFacts(e.facts)}
                        </td>
                        <td className="px-3 py-2 text-xs text-zinc-500">
                          {e.rule ?? <span className="text-zinc-400">egress</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
    </section>
  )
}
