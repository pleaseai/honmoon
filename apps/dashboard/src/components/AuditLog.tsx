import { getAudit } from '../api'
import { describeFacts, formatTime } from '../format'
import { usePolling } from '../hooks'
import { DecisionBadge } from './DecisionBadge'
import { ErrorNote, PageHead, Panel, PanelState } from './ui'

export function AuditLog() {
  const { data, error, loading } = usePolling(getAudit, 2000)
  const events = data ?? []

  return (
    <section className="px-10 pt-8 pb-11 max-md:px-6">
      <div className="mx-auto max-w-[1440px]">
        <PageHead
          eyebrow="Decision trail"
          title="Audit log"
          description="Every policy decision recorded by the gateway, newest first."
          meta={data ? `${events.length} recent events` : undefined}
        />

        {error && <ErrorNote message={error} />}

        <Panel className="reveal" glassClassName="overflow-hidden">
          {data === null
            ? (
                loading
                  ? <PanelState glyph="…">Loading…</PanelState>
                  : <PanelState glyph="✕" tone="error">The audit log could not be loaded.</PanelState>
              )
            : events.length === 0
              ? <PanelState glyph="—">No decisions recorded yet.</PanelState>
              : (
                  <>
                    <div className="overflow-x-auto">
                      <table className="w-full border-collapse">
                        <thead>
                          <tr className="bg-[var(--surface-soft)] text-left">
                            <Th>Time</Th>
                            <Th>Decision</Th>
                            <Th>Request</Th>
                            <Th>Rule</Th>
                          </tr>
                        </thead>
                        <tbody>
                          {events.map(e => (
                            <tr
                              key={e.id}
                              className="h-[57px] transition-colors duration-500 ease-[var(--ease)] not-first:shadow-[inset_0_1px_0_var(--hair)] hover:bg-[color-mix(in_oklch,var(--surface-soft)_72%,transparent)] motion-reduce:transition-none"
                            >
                              <td className="px-[18px] whitespace-nowrap">
                                <time dateTime={e.timestamp} className="font-mono text-[10.5px] text-dim">
                                  {formatTime(e.timestamp)}
                                </time>
                              </td>
                              <td className="px-[18px]">
                                <DecisionBadge decision={e.decision} />
                              </td>
                              <td className="w-full max-w-0 px-[18px]">
                                <code
                                  className="block max-w-[680px] truncate font-mono text-[10.5px]"
                                  title={describeFacts(e.facts)}
                                >
                                  {describeFacts(e.facts)}
                                </code>
                              </td>
                              <td className="px-[18px] font-mono text-[10.5px] whitespace-nowrap text-dim">
                                {e.rule ?? 'egress'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <footer className="flex min-h-[58px] items-center bg-[var(--surface-soft)] px-[18px] text-[10.5px] text-muted">
                      Newest decisions appear first.
                      <span className="meta-mono ml-auto text-[9px]">polling · 2s</span>
                    </footer>
                  </>
                )}
        </Panel>
      </div>
    </section>
  )
}

function Th({ children }: { children: string }) {
  return (
    <th
      scope="col"
      className="h-[43px] px-[18px] font-mono text-[9px] font-semibold tracking-[0.1em] text-dim uppercase"
    >
      {children}
    </th>
  )
}
