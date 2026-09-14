import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'
import {
  checkCoverage,
  checkDocument,
  checkRepository,
  inlinedPages,
  REPO_ROOT,
  RETIRED,
  wikiDocuments,
} from './check-wiki-io-claim'

/** The corrected shape: the invariant stated, then the one file it excepts. */
const ACCURATE = `
The critical invariant: **\`honmoon-core\` is transport-agnostic.** It has no async runtime, no
socket and no network client. Transport-agnostic is not the same as I/O-free: the core opens
exactly one file, the operator's JSONL audit sink in \`audit.rs\`.
`

function details(text: string): string[] {
  return checkDocument(text, 'page').map(problem => problem.detail)
}

describe('checkDocument', () => {
  test('the corrected shape passes', () => {
    expect(checkDocument(ACCURATE, 'page')).toEqual([])
  })

  test('a page naming the invariant without asserting absence owes no exception', () => {
    // `index.md` describes a linked page as covering "the transport-agnostic core".
    expect(details('- [Architecture](/deep-dive/architecture) — the transport-agnostic core.'))
      .toEqual([])
  })

  test('stating what the core lacks without naming the sink fails', () => {
    const withoutException = ACCURATE.replace(
      /Transport-agnostic is not[\s\S]*$/,
      'The proxy feeds it `Facts` and consumes a `Verdict`.\n',
    )
    expect(details(withoutException)).toEqual([expect.stringContaining('without naming the one file')])
  })

  test('markdown emphasis between the negation and the capability does not hide it', () => {
    // What `deep-dive/policy-engine.md` actually said: "has **no** networking dependency".
    expect(details('`honmoon-core` is transport-agnostic and has **no** networking dependency.'))
      .toEqual([expect.stringContaining('without naming the one file')])
  })

  test('underscore emphasis around the negation does not hide it either', () => {
    // The other emphasis syntax: `_no_` is emphasis, `open_sink` is not.
    expect(details('`honmoon-core` is transport-agnostic and has _no_ networking dependency.'))
      .toEqual([expect.stringContaining('without naming the one file')])
  })

  test('an underscore inside a word is an identifier and survives', () => {
    // `plain()` must not tear `open_sink` apart while stripping `_no_`; the sink
    // clause of the rule is written with exactly such identifiers.
    expect(details(
      'A descriptor `open_sink` did not produce. The audit sink is transport-agnostic '
      + 'with no sockets.',
    )).toEqual([])
  })

  test.each(['`tokio`', 'async runtime', 'sockets', 'network client', 'networking dependency'])(
    'rule 2 triggers on "no %s" as the sole capability-absence phrase',
    (capability) => {
      expect(details(`\`honmoon-core\` is transport-agnostic and has no ${capability}.`))
        .toEqual([expect.stringContaining('without naming the one file')])
    },
  )

  test.each(['not', 'never', 'rather than', 'isn\'t', 'no longer', 'instead of'])(
    '"%s" reads as a denial, so the correct sentence is not flagged',
    (cue) => {
      expect(details(`The crate is transport-agnostic ${cue} I/O-free. It opens the audit sink.`))
        .toEqual([])
    },
  )

  test('asserting the crate is I/O-free fails', () => {
    expect(details('The audit sink aside, `honmoon-core` is I/O-free and transport-agnostic.'))
      .toEqual([expect.stringContaining('asserts the crate is I/O-free')])
  })

  test('denying that the crate is I/O-free is the correct sentence and passes', () => {
    for (const denial of [
      'It is transport-agnostic, not I/O-free.',
      'Transport-agnostic is not the same as I/O-free.',
      'The crate is transport-agnostic rather than I/O-free.',
    ]) {
      expect(details(`${denial} It opens the audit sink and nothing else.`)).toEqual([])
    }
  })

  test('a denial in the previous sentence does not license the next one', () => {
    const text = 'It is not a runtime. The crate is I/O-free. It opens the audit sink.'
    expect(details(text)).toEqual([expect.stringContaining('asserts the crate is I/O-free')])
  })

  test.each([
    ['the entire policy engine is unit-tested with zero I/O', 'zero I/O'],
    ['with every byte of I/O pushed to the edges around it', 'every byte of I/O'],
    ['protect the purity of `honmoon-core`', 'purity of `honmoon-core`'],
    ['| Add I/O to `honmoon-core` | Never |', 'Add I/O to `honmoon-core`'],
    ['| transport-agnostic | No `tokio`/sockets/I/O in core |', 'No `tokio`/sockets/I/O in core'],
  ])('the retired wording %p is reported', (retired, quoted) => {
    expect(details(`It opens the audit sink. ${retired}`))
      .toEqual([expect.stringContaining(`retired claim "${quoted}"`)])
  })

  test('one page carrying a retired claim twice reports it twice', () => {
    // `deep-dive/architecture.md` carried the invariant in a paragraph and again
    // in a table, and both had to be found by one run.
    expect(details('It opens the audit sink. zero I/O in the prose, zero I/O in the table.'))
      .toHaveLength(2)
  })
})

describe('wikiDocuments', () => {
  test('covers the pages plus both aggregate files, and skips the agent instructions', () => {
    const documents = wikiDocuments()

    expect(documents).toContain('wiki/deep-dive/architecture.md')
    expect(documents).toContain('wiki/onboarding/staff-engineer-guide.md')
    // Generated by `wiki/.vitepress/gen-llms-full.mjs` from the pages it lists;
    // a page edited without regenerating it leaves the retired wording here.
    expect(documents).toContain('wiki/llms-full.txt')
    expect(documents).toContain('wiki/llms.txt')
    // VitePress `srcExclude`s these — they instruct agents, they are not pages.
    expect(documents).not.toContain('wiki/AGENTS.md')
    expect(documents).not.toContain('wiki/CLAUDE.md')
  })

  test('nothing a build or install left under wiki/ is scanned', () => {
    // `bun install` and `bun run build` inside `wiki/` leave `node_modules` and
    // `.vitepress/dist` behind; CI never installs there, so a scan that picked
    // them up would pass in CI and judge dependency READMEs locally.
    const stray = wikiDocuments().filter(rel =>
      rel.includes('node_modules') || rel.includes('.vitepress'),
    )
    expect(stray).toEqual([])
  })

  test('paths are /-separated on every host, so findings and assertions read the same', () => {
    for (const rel of wikiDocuments()) {
      expect(rel).not.toContain('\\')
    }
  })
})

describe('RETIRED', () => {
  test('every pattern is global, which matchAll requires', () => {
    // `checkDocument` calls `text.matchAll(pattern)`, which throws a TypeError on a
    // non-global regex — so an entry added without `g` breaks the guard at runtime
    // rather than at review. Nothing in the type expresses it; this does.
    expect(RETIRED.filter(rule => !rule.pattern.global)).toEqual([])
  })
})

describe('checkCoverage', () => {
  const aggregate = (): string => readFileSync(join(REPO_ROOT, 'wiki/llms-full.txt'), 'utf8')

  test('the real scan reaches every page the bundle inlines', () => {
    expect(checkCoverage(wikiDocuments(), aggregate())).toEqual([])
    // A bundle that named nothing would satisfy the line above vacuously.
    expect(inlinedPages(aggregate()).length).toBeGreaterThan(10)
  })

  test('a scan that stopped finding pages is reported, not passed', () => {
    // What an `.mdx` migration or a directory rename would leave behind:
    // `wikiDocuments()` appends the two aggregates unconditionally, so the glob
    // returning nothing still yields a readable, retired-wording-free file list.
    const problems = checkCoverage(['wiki/llms.txt', 'wiki/llms-full.txt'], aggregate())

    expect(problems.length).toBe(inlinedPages(aggregate()).length)
    expect(problems[0]!.detail).toContain('the page scan did not reach')
  })
})

describe('checkRepository', () => {
  // The end-to-end assertion over the real wiki rather than the fixtures above:
  // no published page tells a reader that `honmoon-core` performs no I/O (#207).
  test('the published wiki does not reassert the claim #166 retired', () => {
    expect(checkRepository()).toEqual([])
  })
})
