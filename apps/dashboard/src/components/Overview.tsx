import type { AuditEvent, Decision, PendingApproval } from '@honmoon/policy'
import { getApprovals, getAudit } from '../api'
import { describeFacts, formatTime } from '../format'
import { useApprovalActions, usePolling } from '../hooks'
import { ApprovalActions } from './ApprovalActions'
import { DecisionBadge } from './DecisionBadge'
import { ErrorNote, Panel, SectionHead } from './ui'

function count(events: AuditEvent[], ...decisions: Decision[]): number {
  return events.filter(e => decisions.includes(e.decision)).length
}

export function Overview() {
  const { data: audit, error: auditError } = usePolling(getAudit, 2000)
  const { data: approvals, error: approvalsError, refresh } = usePolling(getApprovals, 1500)
  const { busyIds, actionErrors, resolve } = useApprovalActions(refresh)

  const events = audit ?? []
  const pending = approvals?.length ?? 0
  const first = approvals?.[0]
  // Surface fetch failures: without this, a down API renders as zeroes and an
  // empty feed, which reads as "nothing happening" rather than "can't reach it".
  const error = auditError ?? approvalsError
  // Before the first successful audit poll there is nothing to count, so the
  // tiles show a dash instead of a confident zero. The hero also waits for the
  // approvals poll: an unanswered queue is unknown, not empty.
  const auditKnown = audit !== null
  const known = auditKnown && approvals !== null
  // Action failures are keyed by approval id; drop any whose request has since
  // left the queue so a stale note cannot outlive the row it describes.
  const actionFailures = approvals
    ? [...actionErrors].flatMap(([id, message]) => {
        const target = approvals.find(a => a.id === id)
        return target ? [{ id, message: `${target.summary} — ${message}` }] : []
      })
    : []

  const allowed = count(events, 'allowed', 'approved')
  const denied = count(events, 'denied', 'rejected')
  const paused = count(events, 'paused')
  const total = events.length

  const stats = [
    { label: 'Pending approvals', value: approvals ? pending : null, href: '#/approvals', warn: pending > 0 },
    { label: 'Allowed', value: auditKnown ? allowed : null, href: '#/audit' },
    { label: 'Denied', value: auditKnown ? denied : null, href: '#/audit' },
    { label: 'Events recorded', value: auditKnown ? total : null, href: '#/audit' },
  ]

  const status = statusCopy({ error, known, pending, total, allowed, denied })

  return (
    <section>
      <header className="relative overflow-hidden px-10 pt-8 pb-9 max-md:px-6">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(700px_260px_at_10%_-15%,var(--accent-soft),transparent_68%),radial-gradient(560px_240px_at_91%_12%,oklch(70%_0.08_205/0.08),transparent_72%)]"
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute right-9 -bottom-[94px] h-40 w-[580px] -rotate-[5deg] rounded-full shadow-[inset_0_1px_0_var(--accent-line),0_-10px_40px_oklch(81%_0.11_185/0.05)]"
        />
        <div className="relative mx-auto max-w-[1440px]">
          <p className="eyebrow">{status.eyebrow}</p>
          <h1 className="mt-2.5 font-display text-[38px] leading-[1.12] font-semibold tracking-[-0.03em] max-md:text-[30px]">
            {status.title}
            {' '}
            <span className={status.tone === 'error' ? 'text-deny-ink' : 'text-accent-ink [text-shadow:0_0_20px_var(--accent-glow)]'}>
              {status.highlight}
            </span>
            .
          </h1>
          <p className="mt-2 text-[13px] text-muted">{status.summary}</p>
        </div>
      </header>

      <div className="px-10 pb-11 max-md:px-6">
        <div className="mx-auto max-w-[1440px]">
          {error && (
            <ErrorNote message={`Can’t reach the management API — ${error}`} />
          )}
          {actionFailures.map(f => <ErrorNote key={f.id} message={f.message} />)}

          {first && (
            <ApprovalStrip
              approval={first}
              pending={pending}
              busy={busyIds.has(first.id)}
              onApprove={() => resolve(first.id, 'approve')}
              onReject={() => resolve(first.id, 'reject')}
            />
          )}

          <div className="reveal mt-3.5 grid grid-cols-4 gap-3.5 max-md:grid-cols-2">
            {stats.map(s => (
              <a key={s.label} href={s.href} className="bezel">
                <div className="glass px-[18px] py-[17px]">
                  <span className="eyebrow tracking-[0.12em]">{s.label}</span>
                  <strong
                    className={`mt-2 block font-display text-[28px] font-semibold tracking-[-0.025em] tabular-nums ${
                      s.warn ? 'text-warn-ink' : ''
                    }`}
                  >
                    {s.value ?? '—'}
                  </strong>
                </div>
              </a>
            ))}
          </div>

          <div className="reveal mt-3.5 grid grid-cols-[1.65fr_1fr] gap-3.5 max-lg:grid-cols-1">
            <Panel>
              <SectionHead title="Latest decisions" meta="8 most recent" />
              <LatestDecisions events={events.slice(0, 8)} known={auditKnown} error={auditError} />
            </Panel>

            <Panel>
              <SectionHead title="Decision mix" meta="Recorded events" />
              <DecisionMix allowed={allowed} denied={denied} paused={paused} known={auditKnown} />
            </Panel>
          </div>
        </div>
      </div>
    </section>
  )
}

/** Hero copy is derived from live results and never claims what it can't see. */
function statusCopy({
  error,
  known,
  pending,
  total,
  allowed,
  denied,
}: {
  error: string | null
  known: boolean
  pending: number
  total: number
  allowed: number
  denied: number
}): { eyebrow: string, title: string, highlight: string, summary: string, tone: 'ok' | 'error' } {
  if (error) {
    return {
      eyebrow: 'Management API unavailable',
      title: 'Gateway status is',
      highlight: 'unknown',
      summary: 'Live data could not be refreshed.',
      tone: 'error',
    }
  }
  if (!known) {
    return {
      eyebrow: 'Barrier status',
      title: 'Connecting to the',
      highlight: 'gateway',
      summary: 'Waiting for the first audit and approvals polls.',
      tone: 'ok',
    }
  }
  const summary = `${total} events recorded · ${allowed} allowed · ${denied} denied · ${pending} waiting for you`
  if (pending > 0) {
    return {
      eyebrow: `Barrier status / ${pending} waiting for you`,
      title: `${pending} ${pending === 1 ? 'request is' : 'requests are'}`,
      highlight: 'held',
      summary,
      tone: 'ok',
    }
  }
  if (total === 0) {
    return {
      eyebrow: 'Barrier status / no decisions yet',
      title: 'No decisions',
      highlight: 'recorded',
      summary,
      tone: 'ok',
    }
  }
  return {
    eyebrow: 'Barrier status / no requests waiting',
    title: 'Nothing is waiting',
    highlight: 'on you',
    summary,
    tone: 'ok',
  }
}

function ApprovalStrip({
  approval,
  pending,
  busy,
  onApprove,
  onReject,
}: {
  approval: PendingApproval
  pending: number
  busy: boolean
  onApprove: () => void
  onReject: () => void
}) {
  const meta = [
    approval.endpoint ?? approval.domain,
    approval.rule,
    `held ${formatTime(approval.created_at)}`,
  ].filter(Boolean).join(' · ')

  return (
    <Panel className="reveal" glassClassName="flex min-h-[72px] flex-wrap items-center gap-3.5 px-4 py-3">
      <span
        aria-hidden="true"
        className="grid size-10 shrink-0 place-items-center rounded-[13px] bg-warn-soft font-mono text-[15px] font-semibold text-warn-ink"
      >
        ‖
      </span>
      <div className="min-w-0 flex-1">
        <strong className="block truncate text-[13px] font-semibold">{approval.summary}</strong>
        <code className="mt-1 block truncate font-mono text-[10.5px] text-muted">{meta}</code>
      </div>
      {pending > 1 && (
        <a href="#/approvals" className="action action-quiet">
          {pending - 1}
          {' '}
          more in queue
        </a>
      )}
      <ApprovalActions
        summary={approval.summary}
        busy={busy}
        onApprove={onApprove}
        onReject={onReject}
      />
    </Panel>
  )
}

function LatestDecisions({
  events,
  known,
  error,
}: {
  events: AuditEvent[]
  known: boolean
  error: string | null
}) {
  if (events.length === 0) {
    return (
      <p className="px-5 pb-5 text-xs text-muted">
        {known ? 'No activity yet.' : error ? 'Decisions could not be loaded.' : 'Loading…'}
      </p>
    )
  }
  return (
    <ol className="px-2.5 pb-2.5">
      {events.map(e => (
        <li
          key={e.id}
          className="grid min-h-12 grid-cols-[minmax(72px,auto)_100px_minmax(0,1fr)_154px] items-center gap-2.5 rounded-xl px-2.5 odd:bg-[var(--surface-soft)] max-md:grid-cols-[minmax(72px,auto)_100px_minmax(0,1fr)]"
        >
          <time dateTime={e.timestamp} className="font-mono text-[10px] whitespace-nowrap text-dim">
            {formatTime(e.timestamp)}
          </time>
          <DecisionBadge decision={e.decision} />
          <code className="truncate font-mono text-[10.5px]" title={describeFacts(e.facts)}>
            {describeFacts(e.facts)}
          </code>
          <span className="truncate font-mono text-[10px] text-dim max-md:hidden">
            {e.rule ?? 'egress'}
          </span>
        </li>
      ))}
    </ol>
  )
}

/** Share of recorded events per outcome; dashes until the audit poll answers. */
function DecisionMix({
  allowed,
  denied,
  paused,
  known,
}: {
  allowed: number
  denied: number
  paused: number
  known: boolean
}) {
  const total = Math.max(allowed + denied + paused, 1)
  const rows = [
    { label: 'Allowed + approved', value: allowed, color: 'bg-accent' },
    { label: 'Denied + rejected', value: denied, color: 'bg-deny' },
    { label: 'Paused decisions', value: paused, color: 'bg-warn' },
  ]
  return (
    <div className="px-5 pt-1 pb-5">
      <div
        role="img"
        aria-label={known ? rows.map(r => `${r.label}: ${r.value}`).join(', ') : 'Decision mix unknown'}
        className="flex h-[18px] overflow-hidden rounded-full bg-[var(--surface-soft)]"
      >
        {known && rows.map(r => (
          <i key={r.label} className={`h-full ${r.color}`} style={{ width: `${(r.value / total) * 100}%` }} />
        ))}
      </div>
      <ul className="mt-[19px] grid gap-[13px]">
        {rows.map(r => (
          <li key={r.label} className="flex items-center text-[11px] text-muted">
            <i aria-hidden="true" className={`mr-2 size-2 rounded-full ${r.color}`} />
            {r.label}
            <b className="ml-auto font-mono text-[11px] font-semibold text-fg tabular-nums">
              {known ? r.value : '—'}
            </b>
          </li>
        ))}
      </ul>
    </div>
  )
}
