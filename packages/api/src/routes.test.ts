import type { AuditEvent } from '@honmoon/policy'
import { describe, expect, test } from 'bun:test'
import { createFetchHandler } from './routes'

const TOKEN = 'routes-test-token'

/** One event carrying a marker that must not escape without a credential. */
const MARKER = 'marker.internal.example'
const EVENTS: AuditEvent[] = [
  {
    id: 1,
    timestamp: '2026-06-23T05:01:00Z',
    decision: 'denied',
    verdict: 'deny',
    facts: { domain: MARKER },
  },
]

const handle = createFetchHandler({ token: TOKEN, loadEvents: async () => EVENTS })

function get(path: string, headers: Record<string, string> = {}): Promise<Response> {
  return handle(new Request(`http://127.0.0.1:8445${path}`, { headers }))
}

const GATED = ['/api/audit', '/api/audit/stats']

describe('the audit read surface', () => {
  test('serves no data without a credential', async () => {
    for (const path of GATED) {
      const res = await get(path)
      expect(res.status).toBe(401)
      // The assertion is about the data, not the status line: a gate that
      // returned 401 while still writing the body would pass a status check.
      expect(await res.text()).not.toContain(MARKER)
    }
  })

  test('serves no data to a wrong credential', async () => {
    for (const path of GATED) {
      const res = await get(path, { authorization: 'Bearer not-the-token' })
      expect(res.status).toBe(401)
      expect(await res.text()).not.toContain(MARKER)
    }
  })

  test('answers with the management token', async () => {
    const audit = await get('/api/audit', { authorization: `Bearer ${TOKEN}` })
    expect(audit.status).toBe(200)
    expect(await audit.text()).toContain(MARKER)

    const stats = await get('/api/audit/stats', { authorization: `Bearer ${TOKEN}` })
    expect(stats.status).toBe(200)
  })

  test('leaves /healthz open, so a liveness probe needs no token', async () => {
    const res = await get('/healthz')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ status: 'ok' })
  })

  test('does not tell an unauthenticated caller which routes exist', async () => {
    expect((await get('/api/nope')).status).toBe(401)
    expect((await get('/api/nope', { authorization: `Bearer ${TOKEN}` })).status).toBe(404)
  })
})

describe('createFetchHandler', () => {
  test('refuses to build a handler with an empty token', () => {
    // An empty token authenticates `Authorization: Bearer `, which is exactly
    // the unauthenticated mode issue #173 closes. `resolveToken` never yields
    // one, but this is the boundary where the gate is actually constructed.
    expect(() => createFetchHandler({ token: '', loadEvents: async () => EVENTS })).toThrow()
    expect(() => createFetchHandler({ token: '   ', loadEvents: async () => EVENTS })).toThrow()
  })

  test('refuses a padding-only token the rest of the system treats as empty', () => {
    // `String.prototype.trim` leaves U+0085 intact while Rust's `str::trim` and
    // `resolveToken`'s `trimToken` both strip it, so a bare `.trim()` here would
    // build a handler accepting `Authorization: Bearer \u0085` — a credential
    // every other component considers absent.
    for (const padding of ['\u0085', '\uFEFF', '\uFEFF \u0085']) {
      expect(() => createFetchHandler({ token: padding, loadEvents: async () => EVENTS }))
        .toThrow(/empty or padding-only/)
    }
  })
})
