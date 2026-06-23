import type { AuditEvent } from '@honmoon/policy'
import { describe, expect, test } from 'bun:test'
import { auditStats, parseJsonl, queryAudit, queryFromParams } from './audit'

function event(id: number, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id,
    timestamp: `2026-06-23T05:0${id}:00Z`,
    decision: 'denied',
    verdict: 'deny',
    facts: { domain: 'evil.com' },
    ...overrides,
  }
}

describe('parseJsonl', () => {
  test('parses one event per line, skipping blanks and junk', () => {
    const text = [
      JSON.stringify(event(1)),
      '',
      '{ not valid json',
      JSON.stringify(event(2)),
    ].join('\n')
    const events = parseJsonl(text)
    expect(events.map(e => e.id)).toEqual([1, 2])
  })
})

describe('queryAudit', () => {
  const events = [
    event(1, { decision: 'allowed', facts: { domain: 'github.com' } }),
    event(2, { decision: 'denied', facts: { domain: 'evil.com' } }),
    event(3, { decision: 'paused', facts: { domain: 'staging.internal' } }),
  ]

  test('returns newest first', () => {
    expect(queryAudit(events).map(e => e.id)).toEqual([3, 2, 1])
  })

  test('filters by decision', () => {
    expect(queryAudit(events, { decision: 'denied' }).map(e => e.id)).toEqual([2])
  })

  test('filters by domain substring, case-insensitive', () => {
    expect(queryAudit(events, { domain: 'INTERNAL' }).map(e => e.id)).toEqual([3])
  })

  test('filters by since timestamp', () => {
    const since = '2026-06-23T05:02:00Z'
    expect(queryAudit(events, { since }).map(e => e.id)).toEqual([3, 2])
  })

  test('caps at limit', () => {
    expect(queryAudit(events, { limit: 1 }).map(e => e.id)).toEqual([3])
  })
})

describe('auditStats', () => {
  test('counts by decision with all keys present', () => {
    const events = [
      event(1, { decision: 'allowed' }),
      event(2, { decision: 'allowed' }),
      event(3, { decision: 'denied' }),
    ]
    expect(auditStats(events)).toEqual({
      allowed: 2,
      denied: 1,
      paused: 0,
      approved: 0,
      rejected: 0,
    })
  })
})

describe('queryFromParams', () => {
  test('reads supported params and ignores invalid decision', () => {
    const params = new URLSearchParams('limit=5&decision=bogus&domain=gh&since=2026-01-01T00:00:00Z')
    expect(queryFromParams(params)).toEqual({
      limit: 5,
      domain: 'gh',
      since: '2026-01-01T00:00:00Z',
    })
  })

  test('keeps a valid decision', () => {
    expect(queryFromParams(new URLSearchParams('decision=paused')).decision).toBe('paused')
  })
})
