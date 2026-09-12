import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'

// `session.ts` needs `sessionStorage` before the modules below import it.
// Registering twice throws, and `bun test` runs every file in one process, so
// each DOM-using test file registers only if an earlier one has not.
if (!('window' in globalThis)) {
  GlobalRegistrator.register()
}

const { approve, getAudit, NOT_SIGNED_IN } = await import('./api')
const { SESSION_HEADER, captureSession } = await import('./session')

// The shape `/login` emits, which `captureSession` now requires: 64 hex chars.
const SECRET = `${'de'.repeat(30)}beef`

/** Records each call's headers and answers with `body`. */
function recordFetch(body: unknown, status = 200) {
  const calls: { url: string, headers: Record<string, string> }[] = []
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      headers: { ...(init?.headers as Record<string, string> | undefined) },
    })
    return Promise.resolve(new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }))
  }) as typeof fetch
  return calls
}

describe('the management API client', () => {
  const originalFetch = globalThis.fetch

  beforeEach(() => {
    sessionStorage.clear()
    window.location.hash = `#session=${SECRET}`
    captureSession()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  test('a read carries the session secret as a header', async () => {
    // The credential has to be attached here: it is not a cookie, so the
    // browser sends nothing on its own (#188). Losing this line would leave
    // every call unauthenticated, which is why it is asserted and not assumed.
    const calls = recordFetch([])
    await getAudit(5)
    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe('/api/audit?limit=5')
    expect(calls[0]?.headers[SESSION_HEADER]).toBe(SECRET)
  })

  test('an approval write carries the session secret as a header', async () => {
    const calls = recordFetch({ resolved: {} })
    await approve(7)
    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe('/api/approvals/7/approve')
    expect(calls[0]?.headers[SESSION_HEADER]).toBe(SECRET)
  })

  test('a 401 reports "not signed in" rather than an opaque status', async () => {
    recordFetch({ error: 'missing or invalid management token' }, 401)
    // Awaited: an un-awaited `rejects` assertion never runs, so the test would
    // pass whatever the client did with a 401.
    await expect(getAudit()).rejects.toThrow(NOT_SIGNED_IN)
  })
})
