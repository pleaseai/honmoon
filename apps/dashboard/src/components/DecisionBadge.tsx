import type { Decision } from '@honmoon/policy'

/**
 * Serialized decision values, rendered faithfully: `approved` and `rejected`
 * are the outcomes of a previously `paused` request and stay distinct from
 * `allowed` / `denied`. The glyph and label carry the meaning; color supports.
 */
interface Label {
  glyph: string
  text: string
}

const LABELS: Record<Decision, Label> = {
  allowed: { glyph: '✓', text: 'Allowed' },
  approved: { glyph: '✓', text: 'Approved' },
  paused: { glyph: '‖', text: 'Paused' },
  denied: { glyph: '✕', text: 'Denied' },
  rejected: { glyph: '✕', text: 'Rejected' },
}

export function DecisionBadge({ decision }: { decision: Decision }) {
  // The wire value is trusted by type only. A verdict this bundle predates
  // (a stale tab across a gateway upgrade) must render, not unmount the app.
  const label: Label | undefined = LABELS[decision]
  const { glyph, text } = label ?? { glyph: '?', text: decision }
  return (
    <span className={`verdict verdict-${decision}`}>
      <span aria-hidden="true">{glyph}</span>
      {text}
    </span>
  )
}
