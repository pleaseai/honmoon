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
