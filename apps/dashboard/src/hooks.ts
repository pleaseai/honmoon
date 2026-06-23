import { useCallback, useEffect, useState } from 'react'

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
    const run = () => {
      fn()
        .then((d) => {
          if (alive) {
            setData(d)
            setError(null)
          }
        })
        .catch((e: unknown) => {
          if (alive) {
            setError(e instanceof Error ? e.message : String(e))
          }
        })
        .finally(() => {
          if (alive) {
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
