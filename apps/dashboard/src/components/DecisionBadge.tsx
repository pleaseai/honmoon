import type { Decision } from '@honmoon/policy'

const STYLES: Record<Decision, string> = {
  allowed: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300',
  approved: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300',
  denied: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300',
  rejected: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300',
  paused: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
}

export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${STYLES[decision]}`}
    >
      {decision}
    </span>
  )
}
