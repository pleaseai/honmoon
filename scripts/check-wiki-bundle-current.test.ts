import { spawnSync } from 'node:child_process'
import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { describe, expect, test } from 'bun:test'
import { BUNDLE_PATH, PAGE_COUNT, renderBundle } from '../wiki/.vitepress/gen-llms-full.mjs'
import { checkRepository, compareBundle, LIVE } from './check-wiki-bundle-current'
import { REPO_ROOT } from './check-wiki-io-claim'

/** The generator, as a path a subprocess can be pointed at. */
const GENERATOR = fileURLToPath(new URL('../wiki/.vitepress/gen-llms-full.mjs', import.meta.url))

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

  // A renamed page is one drop and one addition at once. Tested because the
  // two halves of that message are joined conditionally, and a regression that
  // dropped either half passed every other test in this file.
  test('a renamed page is reported as both the drop and the addition', () => {
    const renamed = bundle(['wiki/a.md', 'body of a'], ['wiki/c.md', 'body of b'])
    const [problem, ...rest] = compareBundle(generated, renamed)

    expect(rest).toEqual([])
    expect(problem!.detail).toContain('does not inline `wiki/b.md`')
    expect(problem!.detail).toContain('inlines `wiki/c.md`, which the generator does not')
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

  // The check reads the path the generator writes to, spelled once in the
  // generator, so a future move of the bundle cannot leave this reading the old
  // location and calling it current. Built with the same `join` rather than
  // matched as a `/`-suffix, so the assertion is exact and does not depend on
  // the host's separator.
  test('the file it compares is the file the generator overwrites', () => {
    expect(BUNDLE_PATH).toBe(join(REPO_ROOT, 'wiki', 'llms-full.txt'))
    expect(readFileSync(BUNDLE_PATH, 'utf8')).toBe(renderBundle())
  })
})

// Both error branches of `checkRepository` describe repository states that
// cannot be provoked here without renaming a page or deleting the bundle, and
// both were reachable by no test: mutation-testing them to `return []` and to a
// faked successful read each left the whole file green, so a deleted bundle
// would have reported as current. That is the defect #258 is about, inside its
// own guard.
describe('checkRepository failure branches', () => {
  const boom = (message: string) => () => {
    throw new Error(message)
  }

  test('a generator that cannot build the bundle is a finding, not a pass', () => {
    const problems = checkRepository({ render: boom('ENOENT: wiki/deep-dive/gone.md'), read: LIVE.read })

    expect(problems).toHaveLength(1)
    expect(problems[0]!.where).toBe('wiki/.vitepress/gen-llms-full.mjs')
    expect(problems[0]!.detail).toContain('ENOENT: wiki/deep-dive/gone.md')
    expect(problems[0]!.detail).toContain('renamed or deleted')
  })

  test('a bundle that cannot be read is a finding, not a skip', () => {
    const problems = checkRepository({ render: LIVE.render, read: boom('ENOENT: llms-full.txt') })

    expect(problems).toHaveLength(1)
    expect(problems[0]!.where).toBe('wiki/llms-full.txt')
    expect(problems[0]!.detail).toContain('could not be read')
    expect(problems[0]!.detail).toContain('cd wiki && bun .vitepress/gen-llms-full.mjs')
  })

  // Nothing thrown is guaranteed to be an `Error`, and a finding reading
  // `(undefined)` is no use in a file whose whole output is failure messages.
  test('a non-Error throw still produces a readable finding', () => {
    const problems = checkRepository({
      render: () => {
        // The literal is the point: `describe()` has to render a thrown
        // non-Error readably rather than as `undefined`.
        // eslint-disable-next-line no-throw-literal
        throw 'the page list is empty'
      },
      read: LIVE.read,
    })

    expect(problems[0]!.detail).toContain('the page list is empty')
  })
})

// The entry-point guard, which decides whether running the generator writes
// anything. Driven as a subprocess in both directions because that is the only
// way to observe it: this file's own static import has already run by the time
// any test body executes, so an in-process check could not see a top-level
// write at all — it would pass on exactly the regression it guards against.
describe('the generator writes only when it is the entry point', () => {
  test('run as a script, it writes the bundle and says so', () => {
    // Restored unconditionally: the bundle is a tracked file, and a test that
    // rewrote it would repair a stale bundle and hide the very drift the check
    // above exists to report.
    const before = readFileSync(BUNDLE_PATH, 'utf8')
    try {
      const mtime = statSync(BUNDLE_PATH).mtimeMs
      const run = spawnSync('bun', [GENERATOR], { encoding: 'utf8' })

      expect(run.status).toBe(0)
      expect(run.stdout).toContain('wrote llms-full.txt')
      expect(statSync(BUNDLE_PATH).mtimeMs).not.toBe(mtime)
    }
    finally {
      writeFileSync(BUNDLE_PATH, before)
    }
  })

  test('imported rather than run, it writes nothing', () => {
    const probe = [
      `import { statSync } from 'node:fs'`,
      `const path = ${JSON.stringify(BUNDLE_PATH)}`,
      `const before = statSync(path).mtimeMs`,
      `await import(${JSON.stringify(pathToFileURL(GENERATOR).href)})`,
      `console.log(JSON.stringify({ before, after: statSync(path).mtimeMs }))`,
    ].join('\n')
    const run = spawnSync('bun', ['-e', probe], { encoding: 'utf8' })

    expect(run.status).toBe(0)
    const { before, after } = JSON.parse(run.stdout) as { before: number, after: number }
    // The sibling test above proves this mtime moves on a real write, so an
    // unchanged one here means the import wrote nothing rather than that the
    // signal is dead.
    expect(after).toBe(before)
  })
})
