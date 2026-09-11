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

  test('an exposed salt renders its reason, not just a healthy-looking key source', () => {
    // Pins a consumer contract, not a rendering change: `describeFacts` has no
    // exposure-specific branch and needs none. What changed is the population —
    // `hook-salt-exposed` puts `key_source: 'persisted'` inside `RedactionFacts`
    // for the first time, so a value this file previously only ever saw on a
    // healthy key now arrives on a degraded event. The line's first half
    // therefore reads healthy on its own, and `reason` is the only part carrying
    // the bad news. Anything that starts summarising or dropping `reason` breaks
    // the operator's only signal here (issue #141).
    const exposed: FactsSummary = {
      redaction: {
        key_source: 'persisted',
        transport: 'hook',
        reason: 'salt file /home/a/.honmoon/hook-salt is readable beyond its owner (mode 0644) and could not be restricted to 0600',
      },
    }
    expect(describeFacts(exposed)).toContain('mode 0644')
    expect(describeFacts(exposed)).toContain('could not be restricted')
  })

  test('falls back to request facts, then to a dash', () => {
    expect(describeFacts({ domain: 'evil.com' })).toBe('evil.com')
    expect(describeFacts({})).toBe('—')
  })
})
