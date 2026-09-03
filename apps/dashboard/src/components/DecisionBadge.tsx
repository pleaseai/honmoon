import type { Decision } from '@honmoon/policy'

/**
 * Serialized decision values, rendered faithfully: `approved` and `rejected`
 * are the outcomes of a previously `paused` request and stay distinct from
 * `allowed` / `denied`. The glyph and label carry the meaning; color supports.
 */
const LABELS: Record<Decision, { glyph: string, text: string }> = {
  allowed: { glyph: '✓', text: 'Allowed' },
  approved: { glyph: '✓', text: 'Approved' },
  paused: { glyph: '‖', text: 'Paused' },
  denied: { glyph: '✕', text: 'Denied' },
  rejected: { glyph: '✕', text: 'Rejected' },
}

export function DecisionBadge({ decision }: { decision: Decision }) {
  const { glyph, text } = LABELS[decision]
  return (
    <span className={`verdict verdict-${decision}`}>
      <span aria-hidden="true">{glyph}</span>
      {text}
    </span>
  )
}
