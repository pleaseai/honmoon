import type { AuditEvent, Decision } from '@honmoon/policy'
import { getApprovals, getAudit } from '../api'
import { describeFacts, formatTime } from '../format'
import { usePolling } from '../hooks'
import { DecisionBadge } from './DecisionBadge'

function count(events: AuditEvent[], decision: Decision): number {
  return events.filter(e => e.decision === decision).length
}

export function Overview({ onNavigate }: { onNavigate: (view: string) => void }) {
  const { data: audit, error: auditError } = usePolling(getAudit, 2000)
  const { data: approvals, error: approvalsError } = usePolling(getApprovals, 1500)

  const events = audit ?? []
  const pending = approvals?.length ?? 0
  // Surface fetch failures: without this, a down API renders as zeroes and an
  // empty feed, which reads as "nothing happening" rather than "can't reach it".
  const error = auditError ?? approvalsError

  const stats = [
    { label: 'Pending approvals', value: pending, accent: pending > 0 },
    { label: 'Allowed', value: count(events, 'allowed') + count(events, 'approved') },
    { label: 'Denied', value: count(events, 'denied') + count(events, 'rejected') },
    { label: 'Events recorded', value: events.length },
  ]

  return (
    <section>
      <h2 className="mb-4 text-base font-semibold">Overview</h2>

      {error && (
        <p className="mb-4 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-300">
          Can’t reach the management API —
          {' '}
          {error}
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {stats.map(s => (
          <button
            type="button"
            key={s.label}
            onClick={() => onNavigate(s.label === 'Pending approvals' ? 'Approvals' : 'Audit Log')}
            className={`rounded-lg border p-4 text-left ${
              s.accent
                ? 'border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40'
                : 'border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900'
            }`}
          >
            <div className="text-2xl font-semibold tabular-nums">{s.value}</div>
            <div className="mt-1 text-xs text-zinc-500">{s.label}</div>
          </button>
        ))}
      </div>

      <h3 className="mt-8 mb-3 text-sm font-semibold text-zinc-600 dark:text-zinc-400">
        Latest decisions
      </h3>
      {events.length === 0
        ? <p className="text-sm text-zinc-500">No activity yet.</p>
        : (
            <ul className="space-y-1.5">
              {events.slice(0, 8).map(e => (
                <li key={e.id} className="flex items-center gap-3 text-sm">
                  <span className="w-16 shrink-0 font-mono text-xs text-zinc-500">
                    {formatTime(e.timestamp)}
                  </span>
                  <DecisionBadge decision={e.decision} />
                  <span className="truncate font-mono text-xs">{describeFacts(e.facts)}</span>
                </li>
              ))}
            </ul>
          )}
    </section>
  )
}
