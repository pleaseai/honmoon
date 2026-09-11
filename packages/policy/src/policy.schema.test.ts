import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'

/**
 * The `condition` pattern is the editor-side half of a check the Rust loader
 * also makes (`honmoon_core::is_blank_condition`, `condition.trim().is_empty()`).
 * The two must agree, or an author passes validation in their editor and then
 * cannot load the policy - or the reverse.
 *
 * That agreement is not free. `trim` follows Unicode `White_Space`, while a
 * JSON Schema `pattern` is an ECMAScript regex whose `\s` omits U+0085 and
 * adds U+FEFF. Those two code points are the entire difference over the whole
 * of Unicode, and the pattern corrects for both. This test is what keeps it
 * true when either side is edited.
 */

interface ConditionSchema {
  $defs: { rule: { properties: { condition: { pattern: string, minLength: number } } } }
}

const schema = JSON.parse(
  readFileSync(join(import.meta.dir, '../schema/policy.schema.json'), 'utf8'),
) as ConditionSchema

const { pattern, minLength } = schema.$defs.rule.properties.condition
const condition = new RegExp(pattern)

/**
 * Every code point with the Unicode `White_Space` property - what Rust's
 * `char::is_whitespace` returns true for, and so what `trim` removes.
 */
const UNICODE_WHITE_SPACE = [
  0x09,
  0x0A,
  0x0B,
  0x0C,
  0x0D,
  0x20,
  0x85,
  0xA0,
  0x1680,
  0x2000,
  0x2001,
  0x2002,
  0x2003,
  0x2004,
  0x2005,
  0x2006,
  0x2007,
  0x2008,
  0x2009,
  0x200A,
  0x2028,
  0x2029,
  0x202F,
  0x205F,
  0x3000,
]

describe('rule.condition pattern', () => {
  test('agrees with Rust trim() on every single code point', () => {
    const whiteSpace = new Set(UNICODE_WHITE_SPACE)
    const disagreements: string[] = []

    for (let cp = 0; cp <= 0x10FFFF; cp++) {
      // Lone surrogates are not scalar values, so no condition can contain one.
      if (cp >= 0xD800 && cp <= 0xDFFF) {
        continue
      }

      const rustAcceptsIt = !whiteSpace.has(cp)
      if (condition.test(String.fromCodePoint(cp)) !== rustAcceptsIt) {
        disagreements.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`)
      }
    }

    expect(disagreements).toEqual([])
  })

  test('handles the two code points ECMAScript \\s gets wrong', () => {
    // U+0085 is Unicode White_Space but not ECMAScript `\s`: Rust trims it, so
    // a condition of only U+0085 is blank and must be rejected.
    expect(condition.test('\u0085')).toBe(false)
    // U+FEFF is ECMAScript `\s` but not Unicode White_Space: Rust does not trim
    // it, so such a condition loads. It still panics in the CEL parser - that
    // is honmoon issue 154, and not something this pattern claims to catch.
    expect(condition.test('\uFEFF')).toBe(true)
  })

  test('accepts real conditions and rejects the blank forms an author writes', () => {
    for (const valid of ['true', 'sql.verb == \'DROP\'', '  true  ', 'x']) {
      expect(condition.test(valid)).toBe(true)
    }

    for (const blank of ['', ' ', '\t\r\n', '\u00A0', '\u3000']) {
      expect(condition.test(blank)).toBe(false)
    }
  })

  test('minLength still rejects the empty string on its own', () => {
    expect(minLength).toBe(1)
  })
})
