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
 * Overlapping polls commit in order: a response from an older run never
 * overwrites one from a newer run, but it is still applied when nothing newer
 * has landed. An API that is consistently slower than the interval therefore
 * shows stale-but-real data instead of an endless loading state. State is only
 * updated while the effect is mounted, so a request that resolves after
 * unmount (or after `fn`/interval changes) is ignored.
 */
export function usePolling<T>(fn: () => Promise<T>, intervalMs: number): Polled<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  const refresh = useCallback(() => setTick(t => t + 1), [])

  useEffect(() => {
    let alive = true
    // Guard against overlapping polls: a run may commit only if no newer run
    // has committed yet. Comparing against the last *committed* run (not the
    // last *started* one) is what keeps a slow API from discarding every
    // response.
    let latestRun = 0
    let lastCommitted = 0
    const run = () => {
      const runId = ++latestRun
      const commit = (apply: () => void) => {
        if (!alive || runId <= lastCommitted) {
          return
        }
        lastCommitted = runId
        apply()
        setLoading(false)
      }
      fn().then(
        (d) => {
          commit(() => {
            setData(d)
            setError(null)
          })
        },
        (e: unknown) => {
          commit(() => setError(e instanceof Error ? e.message : String(e)))
        },
      )
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
 * Approve/reject actions with one busy flag and one error slot per approval
 * id. Both are keyed by id so concurrent actions on different rows never clear
 * each other's state (a shared single id let a later action re-enable a card
 * while an earlier one was still pending, and a shared error slot let a later
 * action hide an earlier failure). `refresh` re-polls the caller's approval
 * list after a successful resolve; a failed attempt only records that id's
 * error and clears its busy flag.
 */
export function useApprovalActions(refresh: () => void) {
  const [busyIds, setBusyIds] = useState(() => new Set<number>())
  const [actionErrors, setActionErrors] = useState(() => new Map<number, string>())

  const resolve = useCallback(async (id: number, action: 'approve' | 'reject') => {
    setBusyIds(prev => new Set(prev).add(id))
    setActionErrors((prev) => {
      const next = new Map(prev)
      next.delete(id)
      return next
    })
    try {
      await (action === 'approve' ? approve(id) : reject(id))
      refresh()
    }
    catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e)
      setActionErrors(prev => new Map(prev).set(id, message))
    }
    finally {
      setBusyIds((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }, [refresh])

  return { busyIds, actionErrors, resolve }
}
