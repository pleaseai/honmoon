import type { PendingApproval } from '@honmoon/policy'
import { getApprovals } from '../api'
import { formatTime } from '../format'
import { useApprovalActions, usePolling } from '../hooks'
import { ApprovalActions } from './ApprovalActions'
import { ErrorNote, PageHead, Panel, PanelState } from './ui'

export function Approvals() {
  const { data, error, loading, refresh } = usePolling(getApprovals, 1500)
  const { busyIds, actionErrors, resolve } = useApprovalActions(refresh)

  const pending = data ?? []
  const oldest = pending.reduce<PendingApproval | null>(
    (acc, p) => (acc === null || p.created_at < acc.created_at ? p : acc),
    null,
  )

  return (
    <section className="px-10 pt-[30px] pb-11 max-md:px-6">
      <div className="mx-auto max-w-[1440px]">
        <PageHead
          eyebrow="Human decision boundary"
          title="Approval queue"
          description="Requests held by a pause verdict until a person resolves them."
          meta={data ? `${pending.length} pending · polling 1.5s` : 'polling 1.5s'}
        />

        {error && <ErrorNote message={error} />}

        <div className="mb-3.5 grid grid-cols-2 gap-3.5">
          <Panel glassClassName="px-[18px] py-4">
            <span className="eyebrow tracking-[0.1em]">Waiting now</span>
            <strong className="mt-1.5 block font-display text-[23px] font-semibold tabular-nums">
              {data ? pending.length : '—'}
            </strong>
          </Panel>
          <Panel glassClassName="px-[18px] py-4">
            <span className="eyebrow tracking-[0.1em]">Oldest held since</span>
            <strong className="mt-1.5 block font-mono text-[23px] font-semibold tabular-nums">
              {oldest ? formatTime(oldest.created_at) : '—'}
            </strong>
          </Panel>
        </div>

        {data === null
          ? (
              <Panel className="reveal">
                {loading
                  ? <PanelState glyph="…">Loading…</PanelState>
                  : <PanelState glyph="✕" tone="error">The approval queue could not be loaded.</PanelState>}
              </Panel>
            )
          : pending.length === 0
            ? (
                <Panel className="reveal">
                  <PanelState glyph="✓">No requests are waiting for approval.</PanelState>
                </Panel>
              )
            : (
                <ul className="grid gap-3.5">
                  {pending.map(p => (
                    <ApprovalCard
                      key={p.id}
                      approval={p}
                      busy={busyIds.has(p.id)}
                      error={actionErrors.get(p.id)}
                      onApprove={() => resolve(p.id, 'approve')}
                      onReject={() => resolve(p.id, 'reject')}
                    />
                  ))}
                </ul>
              )}
      </div>
    </section>
  )
}

function ApprovalCard({
  approval,
  busy,
  error,
  onApprove,
  onReject,
}: {
  approval: PendingApproval
  busy: boolean
  /** This approval's last failed action, if any; other rows are unaffected. */
  error: string | undefined
  onApprove: () => void
  onReject: () => void
}) {
  return (
    <li className="bezel reveal">
      <div className="glass grid min-h-28 grid-cols-[44px_minmax(0,1fr)_auto] items-center gap-4 p-[17px] max-md:grid-cols-[44px_minmax(0,1fr)]">
        {error && (
          <ErrorNote message={error} className="col-span-full mb-0" />
        )}
        <span
          aria-hidden="true"
          className="grid size-11 place-items-center rounded-[14px] bg-warn-soft font-mono text-[15px] font-semibold text-warn-ink"
        >
          ‖
        </span>
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold" title={approval.summary}>{approval.summary}</h2>
          <p className="mt-1.5 flex flex-wrap items-center gap-x-1.5 font-mono text-[10.5px] text-muted">
            <span>
              held
              {' '}
              <time dateTime={approval.created_at}>{formatTime(approval.created_at)}</time>
            </span>
            {(approval.endpoint ?? approval.domain) && (
              <>
                <span aria-hidden="true">·</span>
                <span>
                  endpoint
                  {' '}
                  <Code>{approval.endpoint ?? approval.domain}</Code>
                </span>
              </>
            )}
            {approval.rule && (
              <>
                <span aria-hidden="true">·</span>
                <span>
                  rule
                  {' '}
                  <Code>{approval.rule}</Code>
                </span>
              </>
            )}
          </p>
        </div>
        <ApprovalActions
          summary={approval.summary}
          busy={busy}
          onApprove={onApprove}
          onReject={onReject}
        />
      </div>
    </li>
  )
}

function Code({ children }: { children: string | undefined }) {
  return (
    <code className="rounded-[5px] bg-[var(--surface-soft)] px-1.5 py-0.5 text-[9.5px] font-medium text-fg">
      {children}
    </code>
  )
}
