import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'bun:test'
import { BUNDLE_PATH, PAGE_COUNT, renderBundle } from '../wiki/.vitepress/gen-llms-full.mjs'
import { checkRepository, compareBundle } from './check-wiki-bundle-current'

/** A bundle in the shape the generator writes, from `[page, body]` pairs. */
function bundle(...docs: [string, string][]): string {
  const header = '# Honmoon — Full Documentation\n\n> blurb\n\n'
  return header + docs
    .map(([page, body]) => `<doc title="T" path="${page}">\n${body}\n</doc>\n\n`)
    .join('')
}

describe('compareBundle', () => {
  const generated = bundle(['wiki/a.md', 'body of a'], ['wiki/b.md', 'body of b'])

  test('a bundle equal to what the generator writes reports nothing', () => {
    expect(compareBundle(generated, generated)).toEqual([])
  })

  // The defect #258 is about, in the smallest form that produces it: a page's
  // text changed and the bundle still holds the old copy.
  test('a section that is not its page any more names that page', () => {
    const stale = bundle(['wiki/a.md', 'body of a'], ['wiki/b.md', 'the OLD body of b'])
    const [problem, ...rest] = compareBundle(generated, stale)

    expect(rest).toEqual([])
    expect(problem!.where).toBe('wiki/llms-full.txt')
    expect(problem!.detail).toContain('`wiki/b.md` section')
    expect(problem!.detail).toContain('cd wiki && bun .vitepress/gen-llms-full.mjs')
  })

  test('two stale sections are two findings, so one fix does not hide the other', () => {
    const stale = bundle(['wiki/a.md', 'OLD a'], ['wiki/b.md', 'OLD b'])
    expect(compareBundle(generated, stale).map(({ detail }) => detail.slice(0, 40)))
      .toHaveLength(2)
  })

  test('a page the generator added and the bundle does not hold is named', () => {
    const [problem] = compareBundle(generated, bundle(['wiki/a.md', 'body of a']))
    expect(problem!.detail).toContain('does not inline `wiki/b.md`')
  })

  test('a page the bundle holds and the generator dropped is named', () => {
    const [problem] = compareBundle(bundle(['wiki/a.md', 'body of a']), generated)
    expect(problem!.detail).toContain('inlines `wiki/b.md`, which the generator does not')
  })

  test('the same pages in a different order is reported as an order difference', () => {
    const swapped = bundle(['wiki/b.md', 'body of b'], ['wiki/a.md', 'body of a'])
    const [problem] = compareBundle(generated, swapped)
    expect(problem!.detail).toContain('in a different order')
  })

  // The property the whole script rests on: the verdict is byte equality, and
  // the attribution only chooses the wording. A difference the section index
  // cannot place has to stay a failure — a localizer that cannot localize must
  // not be able to turn a stale bundle into a pass.
  describe('is empty if and only if the two are byte-identical', () => {
    const cases: [string, string][] = [
      ['a changed header', bundle(['wiki/a.md', 'body of a'], ['wiki/b.md', 'body of b']).replace('blurb', 'BLURB')],
      ['a missing trailing newline', generated.trimEnd()],
      ['a byte appended after the last section', `${generated}footer\n`],
      ['extra spacing between two sections', generated.replace('</doc>\n\n<doc', '</doc>\n\n\n<doc')],
      ['a bundle with no sections at all', '# Honmoon — Full Documentation\n'],
      ['an unterminated section', generated.replace('</doc>\n\n<doc', '<doc')],
    ]

    for (const [what, actual] of cases) {
      test(`${what} is reported rather than passed`, () => {
        expect(actual).not.toBe(generated)
        expect(compareBundle(generated, actual).length).toBeGreaterThan(0)
      })
    }

    test('an identical string reports nothing however odd its shape', () => {
      for (const [, actual] of cases) {
        expect(compareBundle(actual, actual)).toEqual([])
      }
    })
  })
})

describe('checkRepository', () => {
  // The rule this script exists for, over the real wiki. A page edited in any
  // pull request — including this one — fails here until `bun
  // .vitepress/gen-llms-full.mjs` has been run and its output committed.
  test('the committed bundle is what the generator writes today', () => {
    expect(checkRepository()).toEqual([])
  })

  // Without this the assertion above can pass vacuously: a generator that
  // returned its header and nothing else, or a `pages` list emptied by a bad
  // edit, would match a bundle reduced the same way and report nothing.
  test('the comparison is over a real bundle, not an empty one', () => {
    expect(PAGE_COUNT).toBeGreaterThan(10)
    expect(renderBundle().length).toBeGreaterThan(100_000)
  })

  // The check reads the path the generator writes to. Spelled once, in the
  // generator, so a future move of the bundle cannot leave this reading the old
  // location and calling it current.
  test('the file it compares is the file the generator overwrites', () => {
    expect(BUNDLE_PATH.endsWith('/wiki/llms-full.txt')).toBe(true)
    expect(readFileSync(BUNDLE_PATH, 'utf8')).toBe(renderBundle())
  })

  // Importing the generator must not write. If it did, this check would repair
  // the drift it exists to report and could never fail — and every `bun test`
  // run would leave the working tree dirty.
  test('importing the generator leaves the bundle untouched', () => {
    const before = readFileSync(BUNDLE_PATH, 'utf8')
    renderBundle()
    expect(readFileSync(BUNDLE_PATH, 'utf8')).toBe(before)
  })
})
