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

  test('still prefers request facts when both are somehow present', () => {
    expect(describeFacts({ domain: 'evil.com' })).toBe('evil.com')
    expect(describeFacts({})).toBe('—')
  })
})
