import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'

// React DOM needs a document before `createRoot` runs, and static imports are
// hoisted above this call, so the React-side modules are loaded afterwards.
GlobalRegistrator.register()
;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const { act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { useApprovalActions } = await import('./hooks')

type Actions = ReturnType<typeof useApprovalActions>

interface Deferred {
  resolve: (res: Response) => void
  reject: (err: Error) => void
}

/** Hosts the hook and hands each render's return value to the test. */
function Probe({ refresh, onRender }: { refresh: () => void, onRender: (actions: Actions) => void }) {
  onRender(useApprovalActions(refresh))
  return null
}

/**
 * Renders the hook once and exposes its latest return value plus one deferred
 * per POST, keyed by path, so a test can settle requests in any order.
 */
function mount(refresh: () => void) {
  const pending = new Map<string, Deferred>()
  globalThis.fetch = ((input: RequestInfo | URL) => new Promise<Response>((resolve, reject) => {
    pending.set(String(input), { resolve, reject })
  })) as typeof fetch

  let latest: Actions | null = null
  const record = (actions: Actions) => {
    latest = actions
  }
  const container = document.createElement('div')
  const root = createRoot(container)
  act(() => root.render(<Probe refresh={refresh} onRender={record} />))

  return {
    pending,
    get current(): Actions {
      if (latest === null) {
        throw new Error('hook did not render')
      }
      return latest
    },
    unmount: () => act(() => root.unmount()),
  }
}

const ok = () => new Response(null, { status: 200 })
const failed = (path: string) => new Error(`${path} → 500 Internal Server Error`)

describe('useApprovalActions', () => {
  const originalFetch = globalThis.fetch
  let harness: ReturnType<typeof mount>
  let refreshCalls: number

  beforeEach(() => {
    refreshCalls = 0
    harness = mount(() => {
      refreshCalls += 1
    })
  })
  afterEach(() => {
    harness.unmount()
    globalThis.fetch = originalFetch
  })

  test('tracks busy state per id so one request settling leaves the other busy', async () => {
    await act(async () => {
      void harness.current.resolve(1, 'approve')
      void harness.current.resolve(2, 'reject')
    })
    expect([...harness.current.busyIds]).toEqual([1, 2])

    await act(async () => {
      harness.pending.get('/api/approvals/1/approve')!.resolve(ok())
    })
    expect([...harness.current.busyIds]).toEqual([2])
    expect(refreshCalls).toBe(1)
  })

  test('keeps one id’s error when another id’s action runs', async () => {
    await act(async () => {
      void harness.current.resolve(1, 'approve')
    })
    await act(async () => {
      harness.pending.get('/api/approvals/1/approve')!.reject(failed('/api/approvals/1/approve'))
    })
    expect(harness.current.actionErrors.get(1)).toContain('500')

    await act(async () => {
      void harness.current.resolve(2, 'reject')
    })
    await act(async () => {
      harness.pending.get('/api/approvals/2/reject')!.resolve(ok())
    })
    expect(harness.current.actionErrors.get(1)).toContain('500')
    expect(harness.current.actionErrors.has(2)).toBe(false)
    expect(refreshCalls).toBe(1)
  })

  test('clears an id’s previous error when that id is retried, and only refreshes on success', async () => {
    await act(async () => {
      void harness.current.resolve(1, 'reject')
    })
    await act(async () => {
      harness.pending.get('/api/approvals/1/reject')!.reject(failed('/api/approvals/1/reject'))
    })
    expect(harness.current.actionErrors.has(1)).toBe(true)
    expect(harness.current.busyIds.size).toBe(0)
    expect(refreshCalls).toBe(0)

    await act(async () => {
      void harness.current.resolve(1, 'reject')
    })
    expect(harness.current.actionErrors.has(1)).toBe(false)
    expect(harness.current.busyIds.has(1)).toBe(true)
  })
})
