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
    // `hook-salt-exposed` keeps `key_source: 'persisted'` — the bytes really did
    // come from the salt file — so the line's first half reads healthy on its
    // own and the reason is the only part carrying the bad news. It has to
    // survive into what the operator sees (issue #141).
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
