import type { Anchor } from './check-wiki-source-anchors'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'
import { wikiDocuments } from './check-wiki-io-claim'
import {
  checkAnchor,
  checkRepository,
  parseAnchors,
  readCited,
  REPO_ROOT,
  TRACKED,
} from './check-wiki-source-anchors'

const BLOB = 'https://github.com/pleaseai/honmoon/blob/main'

/** An anchor with the fields a rule reads, so each test names only its own. */
function anchor(over: Partial<Anchor> = {}): Anchor {
  return {
    where: 'wiki/page.md',
    line: 1,
    text: 'lib.rs:2-3',
    ref: 'main',
    path: 'crates/honmoon-core/src/lib.rs',
    start: 2,
    end: 3,
    ...over,
  }
}

/** Three lines: an item, its closing brace, then a blank. */
const LINES = ['pub struct Rule {', '}', '']

describe('parseAnchors', () => {
  test('reads the text, the ref, the path and both ends of the range', () => {
    expect(parseAnchors(`see [lib.rs:57-152](${BLOB}/crates/honmoon-core/src/lib.rs#L57-L152).`, 'wiki/p.md'))
      .toEqual([{
        where: 'wiki/p.md',
        line: 1,
        text: 'lib.rs:57-152',
        ref: 'main',
        path: 'crates/honmoon-core/src/lib.rs',
        start: 57,
        end: 152,
      }])
  })

  test('a single-line anchor ends where it starts', () => {
    const [found] = parseAnchors(`[main.rs:620](${BLOB}/crates/honmoon-cli/src/main.rs#L620)`, 'wiki/p.md')
    expect(found).toMatchObject({ start: 620, end: 620 })
  })

  test('a whole-file citation carries no range, and is still checked for existence', () => {
    const [found] = parseAnchors(`[policies/agent.yaml](${BLOB}/policies/agent.yaml)`, 'wiki/p.md')
    expect(found).toMatchObject({ path: 'policies/agent.yaml', start: null, end: null })
  })

  test('the reported line is the document line the citation starts on', () => {
    const source = `one\ntwo\n[lib.rs:1](${BLOB}/crates/honmoon-core/src/lib.rs#L1)\n`
    expect(parseAnchors(source, 'wiki/p.md')[0]!.line).toBe(3)
  })

  test('a non-main ref is captured rather than dropped, so it can be reported', () => {
    const source = `[lib.rs:1](https://github.com/pleaseai/honmoon/blob/99cdd86/crates/honmoon-core/src/lib.rs#L1)`
    expect(parseAnchors(source, 'wiki/p.md')[0]!.ref).toBe('99cdd86')
  })

  test('a link to another repository is not a citation into this tree', () => {
    expect(parseAnchors('[cel](https://github.com/google/cel-spec/blob/main/README.md#L1)', 'wiki/p.md'))
      .toEqual([])
  })
})

describe('checkAnchor', () => {
  test('a range opening on an item passes', () => {
    expect(checkAnchor(anchor({ text: 'lib.rs:1-2', start: 1, end: 2 }), { lines: LINES })).toBeNull()
  })

  test('a range opening on a bare closing brace is reported', () => {
    const problem = checkAnchor(anchor({ text: 'lib.rs:2-3', start: 2, end: 3 }), { lines: LINES })
    expect(problem?.kind).toBe('delimiter')
    expect(problem?.detail).toContain('closes the item above it')
  })

  test('a closing delimiter with a trailing semicolon or comma is still bare', () => {
    for (const close of ['};', '],', ')', '});']) {
      expect(checkAnchor(anchor({ text: 'lib.rs:1', start: 1, end: 1 }), { lines: [close] })?.kind)
        .toBe('delimiter')
    }
  })

  test('a line that opens an item and happens to end in a brace is not a delimiter', () => {
    expect(checkAnchor(anchor({ text: 'lib.rs:1', start: 1, end: 1 }), { lines: ['pub struct Rule {'] })).toBeNull()
  })

  test('a range opening on a blank line is reported', () => {
    const problem = checkAnchor(anchor({ text: 'lib.rs:3', start: 3, end: 3 }), { lines: LINES })
    expect(problem?.kind).toBe('blank')
  })

  test('a range past the end of the file is reported with the length', () => {
    const problem = checkAnchor(anchor({ text: 'lib.rs:2-9', start: 2, end: 9 }), { lines: LINES })
    expect(problem?.kind).toBe('range')
    expect(problem?.detail).toContain('3-line file')
  })

  test('an inverted or zero range is reported rather than resolved', () => {
    expect(checkAnchor(anchor({ text: 'lib.rs:3-1', start: 3, end: 1 }), { lines: LINES })?.kind).toBe('range')
    expect(checkAnchor(anchor({ text: 'lib.rs:0-1', start: 0, end: 1 }), { lines: LINES })?.kind).toBe('range')
  })

  test('link text that disagrees with the fragment is reported', () => {
    const problem = checkAnchor(anchor({ text: 'lib.rs:7-8', start: 1, end: 2 }), { lines: LINES })
    expect(problem?.kind).toBe('text')
    expect(problem?.detail).toContain('`lib.rs:7-8`')
  })

  test('link text carrying no line numbers has nothing to disagree with', () => {
    expect(checkAnchor(anchor({ text: 'the rule struct', start: 1, end: 2 }), { lines: LINES })).toBeNull()
  })

  // The range check runs first, so an out-of-range anchor is reported as such
  // rather than as a text mismatch it also happens to have — one finding per
  // citation, and the one a reader has to act on.
  test('a range past the end is reported before its text is judged', () => {
    expect(checkAnchor(anchor({ text: 'lib.rs:2-9', start: 2, end: 9 }), { lines: LINES })?.kind).toBe('range')
  })

  test('a pinned ref is reported, because this check reads the working tree', () => {
    const problem = checkAnchor(anchor({ ref: '99cdd86' }), { lines: LINES })
    expect(problem?.kind).toBe('ref')
    expect(problem?.detail).toContain('only `main` anchors are verified')
  })

  test('a file that could not be read is the finding, not a skip', () => {
    const problem = checkAnchor(anchor(), { detail: 'cites `gone.rs`, which is not in the repository' })
    expect(problem?.kind).toBe('file')
    expect(problem?.detail).toContain('gone.rs')
  })

  test('a whole-file citation whose file is there has no range to judge', () => {
    expect(checkAnchor(anchor({ text: 'lib.rs', start: null, end: null }), { lines: LINES })).toBeNull()
  })
})

describe('readCited', () => {
  test('the last line of a file that ends in a newline is citable', () => {
    const cited = readCited('crates/honmoon-core/src/lib.rs')
    expect(cited).toHaveProperty('lines')
    const { lines } = cited as { lines: string[] }
    // Source files end with a newline; without trimming the empty tail every
    // `#L<last>` would read as a blank line and be reported.
    expect(lines.at(-1)).not.toBe('')
    const raw = readFileSync(join(REPO_ROOT, 'crates/honmoon-core/src/lib.rs'), 'utf8')
    expect(lines.length).toBe(raw.split('\n').length - 1)
  })

  test('a path with nothing behind it is reported, not skipped', () => {
    expect(readCited('crates/honmoon-core/src/not-a-file.rs'))
      .toEqual({ detail: 'cites `crates/honmoon-core/src/not-a-file.rs`, which is not in the repository' })
  })

  test('a path that climbs out of the repository is reported', () => {
    const cited = readCited('../../../etc/hosts')
    expect(cited).not.toHaveProperty('lines')
    expect((cited as { detail: string }).detail).toContain('../../../etc/hosts')
  })

  test('a directory is not a file a citation can resolve to', () => {
    const cited = readCited('crates/honmoon-core/src')
    expect(cited).not.toHaveProperty('lines')
    expect((cited as { detail: string }).detail).toContain('not a regular file')
  })
})

describe('TRACKED', () => {
  test('no two entries share a key, which would make one of them permanently stale', () => {
    const keys = TRACKED.map(e => `${e.path}:${e.start}:${e.end}:${e.kind}`)
    expect(new Set(keys).size).toBe(keys.length)
  })

  test('every entry names an issue and the pages it is on', () => {
    for (const entry of TRACKED) {
      expect(entry.issue).toBeGreaterThan(0)
      expect(entry.pages).not.toBe('')
    }
  })

  test('nothing on the page #204 repointed is tracked, apart from the row #169 owns', () => {
    const here = TRACKED.filter(e => e.pages.includes('getting-started/policy-authoring.md'))
    expect(here.map(e => e.issue)).toEqual([169])
  })
})

describe('checkRepository', () => {
  // The rule this whole script exists for. A citation added or moved in any
  // pull request — including the one that adds this file — fails here unless it
  // resolves against the source as that pull request leaves it.
  test('every wiki citation resolves, apart from the anchors TRACKED files elsewhere', () => {
    expect(checkRepository().problems).toEqual([])
  })

  // A `TRACKED` entry that matches nothing has outlived its drift: either the
  // anchor was repointed or the page dropped it. Left in, it would be a note
  // telling a future reader that work is outstanding when it is not.
  test('no TRACKED entry has outlived the anchor it describes', () => {
    expect(checkRepository().stale).toEqual([])
  })

  // Without this the failure mode is a vacuous pass: a regression in the link
  // pattern would leave nothing parsed, `problems` empty, and every assertion
  // above green while no citation in the wiki had been resolved at all. The
  // check needs no floor count to rot — it asks each document that *contains* a
  // citation whether any was read out of it.
  test('every document carrying a citation yields one', () => {
    const silent = wikiDocuments().filter((where) => {
      const source = readFileSync(join(REPO_ROOT, where), 'utf8')
      return source.includes(`](${BLOB}`) && parseAnchors(source, where).length === 0
    })
    expect(silent).toEqual([])
  })
})
