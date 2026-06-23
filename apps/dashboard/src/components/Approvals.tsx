import type { PendingApproval } from '@honmoon/policy'
import { useState } from 'react'
import { approve, getApprovals, reject } from '../api'
import { formatTime } from '../format'
import { usePolling } from '../hooks'

export function Approvals() {
  const { data, error, refresh } = usePolling(getApprovals, 1500)
  // Track in-flight ids in a Set so concurrent actions don't clear each
  // other's busy state (a shared single id let a later action re-enable a card
  // while an earlier one was still pending).
  const [busyIds, setBusyIds] = useState(() => new Set<number>())
  const [actionError, setActionError] = useState<string | null>(null)

  async function resolve(id: number, action: 'approve' | 'reject') {
    setBusyIds(prev => new Set(prev).add(id))
    setActionError(null)
    try {
      await (action === 'approve' ? approve(id) : reject(id))
      refresh()
    }
    catch (e: unknown) {
      setActionError(e instanceof Error ? e.message : String(e))
    }
    finally {
      setBusyIds((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }

  const pending = data ?? []
  const message = actionError ?? error

  return (
    <section>
      <header className="mb-4 flex items-baseline gap-3">
        <h2 className="text-base font-semibold">Approval queue</h2>
        <span className="text-sm text-zinc-500">
          {pending.length}
          {' '}
          pending
        </span>
      </header>

      {message && <ErrorNote message={message} />}

      {pending.length === 0
        ? (
            <p className="text-sm text-zinc-500">
              No requests are waiting for approval.
            </p>
          )
        : (
            <ul className="space-y-3">
              {pending.map(p => (
                <ApprovalCard
                  key={p.id}
                  approval={p}
                  busy={busyIds.has(p.id)}
                  onApprove={() => resolve(p.id, 'approve')}
                  onReject={() => resolve(p.id, 'reject')}
                />
              ))}
            </ul>
          )}
    </section>
  )
}

function ApprovalCard({
  approval,
  busy,
  onApprove,
  onReject,
}: {
  approval: PendingApproval
  busy: boolean
  onApprove: () => void
  onReject: () => void
}) {
  return (
    <li className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
      <div className="min-w-0">
        <p className="truncate font-medium">{approval.summary}</p>
        <p className="mt-1 text-xs text-zinc-500">
          held
          {' '}
          {formatTime(approval.created_at)}
          {approval.rule && (
            <>
              {' · rule '}
              <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">
                {approval.rule}
              </code>
            </>
          )}
        </p>
      </div>
      <div className="flex shrink-0 gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={onReject}
          className="rounded border border-rose-300 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-50 disabled:opacity-50 dark:border-rose-800 dark:text-rose-300 dark:hover:bg-rose-950"
        >
          Deny
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={onApprove}
          className="rounded bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50"
        >
          Approve
        </button>
      </div>
    </li>
  )
}

function ErrorNote({ message }: { message: string }) {
  return (
    <p className="mb-3 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-300">
      {message}
    </p>
  )
}
