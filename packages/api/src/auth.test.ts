import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { isAuthorized, resolveToken } from './auth'

describe('isAuthorized', () => {
  test('accepts exactly the configured token as a bearer credential', () => {
    expect(isAuthorized('Bearer s3cr3t-token', 's3cr3t-token')).toBe(true)
  })

  test('rejects a missing, malformed, wrong or differently-sized credential', () => {
    expect(isAuthorized(null, 's3cr3t-token')).toBe(false)
    expect(isAuthorized(undefined, 's3cr3t-token')).toBe(false)
    expect(isAuthorized('s3cr3t-token', 's3cr3t-token')).toBe(false)
    expect(isAuthorized('Basic s3cr3t-token', 's3cr3t-token')).toBe(false)
    // Same length, one byte differs (`0` vs `o`).
    expect(isAuthorized('Bearer s3cr3t-t0ken', 's3cr3t-token')).toBe(false)
    // A matching prefix must not pass, and a length mismatch must not throw —
    // `timingSafeEqual` does when handed unequal-length buffers, which is why
    // both sides are folded through a fixed-width digest first.
    expect(isAuthorized('Bearer s3cr3t', 's3cr3t-token')).toBe(false)
    expect(isAuthorized('Bearer s3cr3t-token-extra', 's3cr3t-token')).toBe(false)
  })
})

describe('resolveToken', () => {
  let dir: string
  const envKeys = ['HONMOON_MGMT_TOKEN', 'HONMOON_HOOK_TOKEN'] as const
  const saved = new Map<string, string | undefined>()

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'honmoon-api-auth-'))
    for (const key of envKeys) {
      saved.set(key, process.env[key])
      delete process.env[key]
    }
  })

  afterEach(() => {
    for (const key of envKeys) {
      const value = saved.get(key)
      if (value === undefined) {
        delete process.env[key]
      }
      else {
        process.env[key] = value
      }
    }
    rmSync(dir, { recursive: true, force: true })
  })

  test('prefers the environment and never persists it', () => {
    process.env.HONMOON_MGMT_TOKEN = 'from-the-environment'
    expect(resolveToken(dir)).toEqual({ token: 'from-the-environment', source: 'environment' })
  })

  test('accepts the deprecated HONMOON_HOOK_TOKEN, with HONMOON_MGMT_TOKEN winning', () => {
    process.env.HONMOON_HOOK_TOKEN = 'deprecated'
    expect(resolveToken(dir).token).toBe('deprecated')
    process.env.HONMOON_MGMT_TOKEN = 'current'
    expect(resolveToken(dir).token).toBe('current')
  })

  test('mints an owner-only token on first use and reuses it afterwards', () => {
    const first = resolveToken(dir)
    expect(first.source).toBe('generated')
    expect(first.token).toMatch(/^[0-9a-f]{64}$/)

    const path = join(dir, 'mgmt-token')
    expect(readFileSync(path, 'utf8')).toBe(first.token)
    // A credential another local user can read is the exposure this closes.
    expect(statSync(path).mode & 0o777).toBe(0o600)

    // The Rust gateway reads this same file, so a second resolution that minted
    // a different token would silently disagree with it.
    const second = resolveToken(dir)
    expect(second.token).toBe(first.token)
    expect(second.source).toBe('persisted')
  })

  test('replaces an empty token file rather than serving an empty credential', () => {
    const path = join(dir, 'mgmt-token')
    writeFileSync(path, '\n')
    const resolved = resolveToken(dir)
    expect(resolved.source).toBe('generated')
    expect(resolved.token).toMatch(/^[0-9a-f]{64}$/)
  })

  test('aborts on an unreadable token file instead of minting a second one', () => {
    // A directory where the file should be: the read fails with something other
    // than ENOENT, which must not be recovered from by generating a token that
    // disagrees with whatever holds the real one.
    mkdirSync(join(dir, 'mgmt-token'))
    expect(() => resolveToken(dir)).toThrow()
  })
})
