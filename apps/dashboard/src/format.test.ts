import type { FactsSummary } from '@honmoon/policy'
import { describe, expect, test } from 'bun:test'
import { describeFacts } from './format'

describe('describeFacts', () => {
  test('describes a degradation ahead of the protocol branches', () => {
    // A degraded event carries none of the request facts the other branches
    // look for, so without this branch it renders as an unexplained dash — the
    // one event whose whole purpose is to be noticed.
    const facts: FactsSummary = {
      redaction: { key_source: 'fallback', transport: 'hook', reason: 'unwritable HOME' },
    }
    expect(describeFacts(facts)).toBe('redaction key: fallback (hook) — unwritable HOME')
  })

  test('a degradation wins over request facts when both are present', () => {
    // The precedence the branch order actually implements: a degraded event
    // describes the engine, so it outranks whatever request facts came along.
    const both: FactsSummary = {
      domain: 'evil.com',
      redaction: { key_source: 'unpersisted', transport: 'gateway', reason: 'lost publish race' },
    }
    expect(describeFacts(both)).toBe('redaction key: unpersisted (gateway) — lost publish race')
  })

  test('falls back to request facts, then to a dash', () => {
    expect(describeFacts({ domain: 'evil.com' })).toBe('evil.com')
    expect(describeFacts({})).toBe('—')
  })
})
