import { useCallback, useEffect, useState } from 'react'
import { approve, reject } from './api'

export interface Polled<T> {
  data: T | null
  error: string | null
  loading: boolean
  refresh: () => void
}

/**
 * Poll `fn` every `intervalMs`, exposing the latest data/error and a manual
 * `refresh`. Pass a stable `fn` reference (e.g. a module-level API function) so
 * the polling interval isn't torn down and recreated on every render.
 *
 * State is only updated while the effect is mounted, so a slow in-flight request
 * that resolves after unmount (or after `fn`/interval changes) is ignored.
 */
export function usePolling<T>(fn: () => Promise<T>, intervalMs: number): Polled<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  const refresh = useCallback(() => setTick(t => t + 1), [])

  useEffect(() => {
    let alive = true
    // Guard against overlapping polls: a slow earlier request must not
    // overwrite newer state with stale data, so only the latest run commits.
    let latestRun = 0
    const run = () => {
      const runId = ++latestRun
      fn()
        .then((d) => {
          if (alive && runId === latestRun) {
            setData(d)
            setError(null)
          }
        })
        .catch((e: unknown) => {
          if (alive && runId === latestRun) {
            setError(e instanceof Error ? e.message : String(e))
          }
        })
        .finally(() => {
          if (alive && runId === latestRun) {
            setLoading(false)
          }
        })
    }
    run()
    const id = setInterval(run, intervalMs)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [fn, intervalMs, tick])

  return { data, error, loading, refresh }
}

/**
 * Approve/reject actions with one busy flag per approval id. Ids are tracked
 * in a Set so concurrent actions don't clear each other's busy state (a shared
 * single id let a later action re-enable a card while an earlier one was still
 * pending). `refresh` re-polls the caller's approval list after a successful
 * resolve; a failed attempt only surfaces `actionError` and clears the busy
 * flag.
 */
export function useApprovalActions(refresh: () => void) {
  const [busyIds, setBusyIds] = useState(() => new Set<number>())
  const [actionError, setActionError] = useState<string | null>(null)

  const resolve = useCallback(async (id: number, action: 'approve' | 'reject') => {
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
  }, [refresh])

  return { busyIds, actionError, resolve }
}
