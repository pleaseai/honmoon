/**
 * Deny / Approve pair for one held request. Approve is the only solid cyan
 * action in the group; Deny is a red-tinted outline. Both lock while that
 * approval's own busy flag is set, so sibling rows stay independent.
 */
export function ApprovalActions({
  summary,
  busy,
  onApprove,
  onReject,
}: {
  /** Names the request for assistive technology, e.g. "Approve: DROP TABLE…". */
  summary: string
  busy: boolean
  onApprove: () => void
  onReject: () => void
}) {
  return (
    <div className="flex shrink-0 gap-2" aria-busy={busy || undefined}>
      <button
        type="button"
        className="action action-deny"
        disabled={busy}
        onClick={onReject}
        aria-label={busy ? `Resolving… ${summary}` : `Deny: ${summary}`}
      >
        {busy
          ? 'Resolving…'
          : (
              <>
                <span aria-hidden="true">✕</span>
                Deny
              </>
            )}
      </button>
      <button
        type="button"
        className="action action-approve"
        disabled={busy}
        onClick={onApprove}
        aria-label={busy ? `Resolving… ${summary}` : `Approve: ${summary}`}
      >
        {busy
          ? 'Resolving…'
          : (
              <>
                <span aria-hidden="true">✓</span>
                Approve
              </>
            )}
      </button>
    </div>
  )
}
