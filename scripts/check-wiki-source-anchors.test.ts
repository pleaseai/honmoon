import type { Anchor, Tracked } from './check-wiki-source-anchors'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'
import { wikiDocuments } from './check-wiki-io-claim'
import {
  bundleOwner,
  bundleSections,
  checkAnchor,
  checkLinksRead,
  checkRepository,
  defers,
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

  test('a `?plain=1` permalink is read, and the query is not part of the path', () => {
    const [found] = parseAnchors(`[lib.rs:12-34](${BLOB}/crates/honmoon-core/src/lib.rs?plain=1#L12-L34)`, 'wiki/p.md')
    expect(found).toMatchObject({ path: 'crates/honmoon-core/src/lib.rs', start: 12, end: 34 })
  })

  // GitHub emits this for a partial multi-line selection. The columns narrow
  // which characters are highlighted, not which lines are cited.
  test('a column-qualified permalink resolves to its lines', () => {
    const [found] = parseAnchors(`[lib.rs:12-34](${BLOB}/crates/honmoon-core/src/lib.rs#L12C3-L34C10)`, 'wiki/p.md')
    expect(found).toMatchObject({ path: 'crates/honmoon-core/src/lib.rs', start: 12, end: 34 })
  })

  // CommonMark's angle-bracketed destination. Unwidened it matched neither
  // `ANCHOR` nor `BLOB_LINK`, so the citation was uncounted as well as
  // unparsed — the one shape rule 6 could not report.
  test('an angle-bracketed destination is read like a bare one', () => {
    const [found] = parseAnchors(`[lib.rs:12-34](<${BLOB}/crates/honmoon-core/src/lib.rs#L12-L34>)`, 'wiki/p.md')
    expect(found).toMatchObject({ path: 'crates/honmoon-core/src/lib.rs', start: 12, end: 34 })
  })

  test('an angle-bracketed whole-file citation keeps its path off the bracket', () => {
    const [found] = parseAnchors(`[agent.yaml](<${BLOB}/policies/agent.yaml>)`, 'wiki/p.md')
    expect(found).toMatchObject({ path: 'policies/agent.yaml', start: null, end: null })
  })

  // A stray space after `](` is a typo, not a decision, and CommonMark renders
  // it as a normal link — the likeliest way a real page lands in a shape
  // neither pattern sees.
  test('whitespace either side of the destination is permitted', () => {
    const [found] = parseAnchors(`[lib.rs:12-34](\t ${BLOB}/crates/honmoon-core/src/lib.rs#L12-L34 )`, 'wiki/p.md')
    expect(found).toMatchObject({ path: 'crates/honmoon-core/src/lib.rs', start: 12, end: 34 })
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

  // The file half of rule 4. Numbers that happen to line up are what makes it
  // invisible: the citation reads as verified and sends the reader elsewhere.
  test('text naming a different file from the link is reported', () => {
    const problem = checkAnchor(anchor({ text: 'engine.rs:1-2', start: 1, end: 2 }), { lines: LINES })
    expect(problem?.kind).toBe('text')
    expect(problem?.detail).toContain('the text names one file and the link opens another')
  })

  // Link text abbreviates its path routinely, so only the last segment counts.
  test('a label that abbreviates the cited path agrees with it', () => {
    expect(checkAnchor(
      anchor({ text: 'cli/index.ts:1-2', path: 'packages/cli/src/index.ts', start: 1, end: 2 }),
      { lines: LINES },
    )).toBeNull()
  })

  // Eleven published citations name their source this way.
  test('a label that is not filename-shaped is not judged as one', () => {
    for (const text of ['ADR-0002:1-2', '0002:1-2', 'tracker:1-2']) {
      expect(checkAnchor(
        anchor({ text, path: '.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md', start: 1, end: 2 }),
        { lines: LINES },
      )).toBeNull()
    }
  })

  // Both halves wrong: the file is the one reported, because it is the one a
  // reader acts on first.
  test('a wrong file is reported ahead of wrong numbers', () => {
    const problem = checkAnchor(anchor({ text: 'engine.rs:7-8', start: 1, end: 2 }), { lines: LINES })
    expect(problem?.detail).toContain('names one file')
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

  // The worst form of a text/URL disagreement: the reader is given precise
  // lines and the link lands on none of them.
  test('text promising a range the link does not carry is reported', () => {
    const problem = checkAnchor(anchor({ text: 'lib.rs:100-120', start: null, end: null }), { lines: LINES })
    expect(problem?.kind).toBe('text')
    expect(problem?.detail).toContain('links no line range at all')
  })

  // Both rules fire on this anchor; rule 4 is the one reported, because the
  // remedy differs and `TRACKED` keys on which rule fired.
  test('disagreeing text is reported ahead of a blank first line', () => {
    expect(checkAnchor(anchor({ text: 'lib.rs:7-8', start: 3, end: 3 }), { lines: LINES })?.kind)
      .toBe('text')
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

  test('every entry names an issue and at least one page, which the match reads', () => {
    for (const entry of TRACKED) {
      expect(entry.issue).toBeGreaterThan(0)
      expect(entry.pages.length).toBeGreaterThan(0)
    }
  })

  test('nothing on the page #204 repointed is tracked, apart from the row #169 owns', () => {
    const here = TRACKED.filter(e => e.pages.includes('getting-started/policy-authoring.md'))
    expect(here.map(e => e.issue)).toEqual([169])
  })

  // The bundle is generated from the pages, so no entry may name it — its
  // occurrence is deferred by the entry still matching the page that occurrence
  // was generated from, not by a listing of its own.
  test('no entry defers the generated bundle directly', () => {
    expect(TRACKED.flatMap(e => e.pages).filter(page => page.endsWith('.txt'))).toEqual([])
  })

  // #253 enumerated thirty-five anchors and is closed. An entry still naming it
  // would print work as outstanding against an issue nobody can read the state
  // of, and the ledger is an instruction to whoever runs this next. The five
  // that outlived it were re-attributed to the page issues that own them
  // (#260, #261, #263), not deleted — deleting one would show up in
  // `checkRepository().problems`, which is what makes this pair a proof that
  // the other thirty were repointed rather than delisted.
  test('nothing is still deferred to #253, which those thirty repoints closed', () => {
    expect(TRACKED.filter(entry => entry.issue === 253)).toEqual([])
  })
})

// The three properties the ledger's own doc comment promises. Each is a way the
// suppression leaked before review: by rule, by anchor, and by page.
describe('defers', () => {
  const entry: Tracked = {
    path: 'crates/honmoon-core/src/engine.rs',
    start: 59,
    end: 60,
    kind: 'blank',
    issue: 169,
    pages: ['getting-started/policy-authoring.md'],
  }
  const cited = anchor({
    where: 'wiki/getting-started/policy-authoring.md',
    path: 'crates/honmoon-core/src/engine.rs',
    start: 59,
    end: 60,
  })

  test('defers its own anchor, rule and page', () => {
    expect(defers(entry, cited, 'blank')).toBe(true)
  })

  // `kind` is in the key so an entry recorded for a blank-line start cannot
  // absorb the range failure a shrinking file would produce on the same anchor.
  test('does not defer a different rule on the same anchor', () => {
    expect(defers(entry, cited, 'range')).toBe(false)
  })

  test('does not defer the same anchor copied onto another page', () => {
    expect(defers(entry, { ...cited, where: 'wiki/deep-dive/policy-engine.md' }, 'blank')).toBe(false)
  })

  test('does not defer a different range in the same file', () => {
    expect(defers(entry, { ...cited, start: 61, end: 62 }, 'blank')).toBe(false)
  })

  // How the bundle pass asks the question: the occurrence's own `where` is
  // `wiki/llms-full.txt`, which no entry lists, so the page it was generated
  // from is passed explicitly.
  test('judges an explicit page instead of the anchor’s own document', () => {
    const inBundle = { ...cited, where: 'wiki/llms-full.txt' }
    expect(defers(entry, inBundle, 'blank')).toBe(false)
    expect(defers(entry, inBundle, 'blank', 'wiki/getting-started/policy-authoring.md')).toBe(true)
    expect(defers(entry, inBundle, 'blank', 'wiki/deep-dive/policy-engine.md')).toBe(false)
  })
})

// The attribution that makes a bundle occurrence answerable per page. Without
// it, an entry naming several pages had one page's stale bundle copy hidden by
// a sibling page that still carried the anchor.
describe('bundleSections', () => {
  const bundle = [
    'preamble',
    '<doc title="A" path="wiki/a.md">',
    'body of a',
    '</doc>',
    '',
    '<doc title="B" path="wiki/b.md">',
    'body of b',
    '</doc>',
  ].join('\n')

  test('names every inlined page with the lines its section spans', () => {
    expect(bundleSections(bundle)).toEqual([
      { line: 2, end: 4, page: 'wiki/a.md' },
      { line: 6, end: 8, page: 'wiki/b.md' },
    ])
  })

  test('a marker quoted inside a page does not re-attribute what follows', () => {
    expect(bundleSections('  <doc title="X" path="wiki/x.md">')).toEqual([])
  })

  test('attributes each line to the section it falls in', () => {
    const sections = bundleSections(bundle)
    expect(bundleOwner(sections, 1)).toBeNull()
    expect(bundleOwner(sections, 2)).toBe('wiki/a.md')
    expect(bundleOwner(sections, 4)).toBe('wiki/a.md')
    expect(bundleOwner(sections, 7)).toBe('wiki/b.md')
  })

  // The section's end is read, not inferred from where the next one opens.
  // Otherwise everything the generator writes between or after sections — its
  // header today, a footer tomorrow — is attributed to the page above it, and
  // a tracked finding placed there would be deferred by a page that does not
  // contain it (cubic, #254).
  test('a line between two sections belongs to neither', () => {
    expect(bundleOwner(bundleSections(bundle), 5)).toBeNull()
  })

  test('a line after the last `</doc>` belongs to no page', () => {
    const sections = bundleSections(`${bundle}\n\nfooter written by the generator`)
    expect(bundleOwner(sections, 10)).toBeNull()
  })

  // Fail-loud: a bundle whose shape this cannot read should defer nothing,
  // rather than hand one page everything that follows an unclosed marker.
  test('an unterminated section spans only its own line', () => {
    const sections = bundleSections('<doc title="A" path="wiki/a.md">\nbody\nmore body')
    expect(sections).toEqual([{ line: 1, end: 1, page: 'wiki/a.md' }])
    expect(bundleOwner(sections, 2)).toBeNull()
  })

  test('the real bundle is indexed by the pages the scan opened', () => {
    const pages = bundleSections(readFileSync(join(REPO_ROOT, 'wiki/llms-full.txt'), 'utf8'))
      .map(({ page }) => page)
    expect(pages.length).toBeGreaterThan(0)
    expect(pages.filter(page => !wikiDocuments().includes(page))).toEqual([])
  })

  // Every section the generator writes is closed, so no page's span runs to the
  // end of the file — the property the attribution above depends on.
  test('every section in the real bundle is terminated', () => {
    const sections = bundleSections(readFileSync(join(REPO_ROOT, 'wiki/llms-full.txt'), 'utf8'))
    expect(sections.filter(({ line, end }) => end === line)).toEqual([])
  })
})

describe('checkLinksRead', () => {
  test('a document whose every blob link parsed reports nothing', () => {
    expect(checkLinksRead(`[lib.rs:1](${BLOB}/crates/honmoon-core/src/lib.rs#L1)`, 'wiki/p.md')).toEqual([])
  })

  // A link text carrying `]` defeats `ANCHOR` entirely: the citation is not
  // misparsed, it is absent. This rule is what makes that loud, and it is the
  // reason `ANCHOR` does not have to grow a case per unparseable shape.
  test('a blob link the anchor pattern cannot read is reported by count', () => {
    const source = `[lib.rs [old]:1-2](${BLOB}/crates/honmoon-core/src/lib.rs#L1-L2)`
    expect(parseAnchors(source, 'wiki/p.md')).toEqual([])
    const [problem] = checkLinksRead(source, 'wiki/p.md')
    expect(problem?.kind).toBe('coverage')
    expect(problem?.line).toBeNull()
    expect(problem?.detail).toContain('1 went unresolved')
  })

  test('the count is per document, so one unread link among several is still reported', () => {
    const source = `[a:1](${BLOB}/README.md#L1) and [b [x]:1](${BLOB}/README.md#L1)`
    expect(parseAnchors(source, 'wiki/p.md')).toHaveLength(1)
    expect(checkLinksRead(source, 'wiki/p.md')).toHaveLength(1)
  })

  // A link title is legal and the parser stops at it. Counted, so it reports.
  test('a destination carrying a title is counted, then reported', () => {
    const source = `[lib.rs:1](${BLOB}/crates/honmoon-core/src/lib.rs#L1 "the policy model")`
    expect(parseAnchors(source, 'wiki/p.md')).toEqual([])
    expect(checkLinksRead(source, 'wiki/p.md')[0]?.kind).toBe('coverage')
  })

  // A reference link resolves through a definition elsewhere in the document,
  // which neither pattern follows. The counter sees the definition, so the
  // document is reported and the page spells the citation inline — without
  // this the whole shape was invisible to both halves.
  test('a reference definition is counted, then reported', () => {
    const source = `see [lib.rs:1][x]\n\n[x]: ${BLOB}/crates/honmoon-core/src/lib.rs#L1\n`
    expect(parseAnchors(source, 'wiki/p.md')).toEqual([])
    expect(checkLinksRead(source, 'wiki/p.md')[0]?.kind).toBe('coverage')
  })

  // The counter is looser than the parser on purpose. A newline after `](` is
  // legal markdown that `ANCHOR` refuses, so it has to land as a report rather
  // than as silence — the failure mode rule 6 exists to prevent.
  test('a destination on the next line is counted, then reported', () => {
    const source = `[lib.rs:1](\n${BLOB}/crates/honmoon-core/src/lib.rs#L1)`
    expect(parseAnchors(source, 'wiki/p.md')).toEqual([])
    expect(checkLinksRead(source, 'wiki/p.md')[0]?.kind).toBe('coverage')
  })

  // The residue of accepting the angle-bracketed form: a space is legal inside
  // the brackets and nowhere else, so such a destination still does not parse.
  // It is counted now, which is the difference between reported and invisible.
  test('an angle-bracketed destination carrying a space is counted, then reported', () => {
    const source = `[lib.rs:1](<${BLOB}/crates/honmoon-core/src lib.rs#L1>)`
    expect(parseAnchors(source, 'wiki/p.md')).toEqual([])
    expect(checkLinksRead(source, 'wiki/p.md')[0]?.kind).toBe('coverage')
  })
})

describe('checkRepository', () => {
  // The rule this whole script exists for. A citation added or moved in any
  // pull request — including the one that adds this file — fails here unless it
  // resolves against the source as that pull request leaves it.
  test('every wiki citation resolves, apart from the anchors TRACKED files elsewhere', () => {
    expect(checkRepository().problems).toEqual([])
  })

  // A page a `TRACKED` entry names that no longer produces its finding has
  // outlived the drift: either the anchor was repointed or the page dropped it.
  // Left in, it would be a note telling a future reader that work is
  // outstanding when it is not — and, until review, a page that kept a sibling
  // page's stale bundle copy deferred.
  test('no TRACKED page has outlived the anchor it describes', () => {
    expect(checkRepository().stale).toEqual([])
  })

  // Rules 6 and 7, over the real corpus. Without them the failure mode is a
  // vacuous pass: a regression in the link pattern or in `wikiDocuments()`
  // leaves nothing parsed, `problems` empty, and every assertion above green
  // while no citation in the wiki was resolved at all. Neither needs a floor
  // count to rot — one asks each document whether its own links were read, the
  // other asks the generated bundle whether the scan reached the pages it
  // inlines.
  test('every blob link in every wiki document parsed as a citation', () => {
    const unread = wikiDocuments().flatMap(where =>
      checkLinksRead(readFileSync(join(REPO_ROOT, where), 'utf8'), where))
    expect(unread).toEqual([])
  })

  test('nothing the scan missed is reported as a coverage gap', () => {
    expect(checkRepository().problems.filter(p => p.kind === 'coverage')).toEqual([])
  })
})

const CONTROL_PLANE = 'wiki/deep-dive/control-plane.md'
const MGMT_LIB = 'crates/honmoon-mgmt/src/lib.rs'

/**
 * Every row of `control-plane.md`'s route table, as label / binding / handler.
 *
 * The binding is read out of `router()` as well, so a renamed handler fails
 * here rather than leaving this list checking a name nothing answers to.
 */
const ROUTE_ROWS = [
  ['`/api/audit?limit=N`', '.route("/audit", get(list_audit))', 'list_audit'],
  ['`/api/approvals`', '.route("/approvals", get(list_approvals))', 'list_approvals'],
  ['`/api/approvals/{id}/approve`', '.route("/approvals/{id}/approve", post(approve))', 'approve'],
  ['`/api/approvals/{id}/reject`', '.route("/approvals/{id}/reject", post(reject))', 'reject'],
  ['`/api/policy`', '.route("/policy", get(get_policy))', 'get_policy'],
  ['`/healthz`', '.route("/healthz", get(healthz))', 'healthz'],
  ['anything else', '.fallback(static_handler)', 'static_handler'],
] as const

/**
 * What `control-plane.md`'s `honmoon-mgmt` citations actually display.
 *
 * Rule 3 judges a range's *first line* and nothing else, so a range that slid
 * onto a content line reads as fine: every row of this table named an axum
 * handler while displaying the `HookSalt`/`HookKey` constructors ~500 lines
 * above it, and the scan stayed quiet through all seven (#266). The module doc
 * says nothing mechanical can close that in general, and that stands — it would
 * have to know what the prose means. This page is the case where it does not
 * have to: the prose names the handler, so the range can be required to show
 * the function `router()` binds to that route.
 *
 * Deliberately carries no line numbers of its own. Both halves are read out of
 * the tree — the handler from the route binding, the range from the citation —
 * so the next commit that moves `lib.rs` fails here naming the row to repoint,
 * instead of drifting silently a second time.
 */
describe('control-plane.md shows the management API it cites', () => {
  const page = readFileSync(join(REPO_ROOT, CONTROL_PLANE), 'utf8')
  const source = readFileSync(join(REPO_ROOT, MGMT_LIB), 'utf8')
  const read = readCited(MGMT_LIB)
  if (!('lines' in read)) {
    throw new Error(`${MGMT_LIB}: ${read.detail}`)
  }
  const { lines } = read

  /** The lines one citation displays, as a reader following the link sees them. */
  function shown(anchor: Anchor): string {
    expect(anchor.path).toBe(MGMT_LIB)
    return lines.slice(anchor.start! - 1, anchor.end!).join('\n')
  }

  /** The first `count` citations at or after `marker`, which the prose precedes. */
  function after(marker: string, count: number): Anchor[] {
    const at = page.indexOf(marker)
    expect(at).toBeGreaterThanOrEqual(0)
    return parseAnchors(page.slice(at), CONTROL_PLANE).slice(0, count)
  }

  test.each(ROUTE_ROWS)('the %s row shows the handler router() binds to it', (label, binding, handler) => {
    expect(source).toContain(binding)
    const row = page.split('\n').find(line => line.startsWith(`| ${label} |`))
    expect(row).toBeDefined()
    const anchors = parseAnchors(row!, CONTROL_PLANE)
    expect(anchors).toHaveLength(1)
    expect(shown(anchors[0]!)).toContain(`fn ${handler}(`)
  })

  // The two citations #266 filed as stale that are not: both already point at
  // the function the sentence names. Pinned rather than repointed, so the next
  // reader of that issue does not re-derive them a third time.
  test('the credential paragraph shows the two checks it names', () => {
    const [authorized, login] = after('Every `/api` row above requires the management token', 2)
    expect(shown(authorized!)).toContain('fn authorized(')
    expect(shown(login!)).toContain('fn login(')
  })

  test('the SPA-fallback 404 detail shows the guard that answers it', () => {
    const [guard] = after('One careful detail: the SPA fallback', 1)
    expect(shown(guard!)).toContain('path.starts_with("api/")')
    expect(shown(guard!)).toContain('StatusCode::NOT_FOUND')
  })

  // A `<!-- Sources: … -->` comment is not a link, so no rule above resolves it
  // and the checker never sees it at all — the reason this one sat ~540 lines
  // off the handlers its diagram draws.
  test('the approvals diagram names the handlers it draws', () => {
    const comment = page.split('\n')
      .find(line => line.startsWith('<!-- Sources:') && line.includes('Approvals.tsx'))
    expect(comment).toBeDefined()
    const range = new RegExp(`${MGMT_LIB.replace(/[./]/g, '\\$&')}:(\\d+)-(\\d+)`).exec(comment!)
    expect(range).not.toBeNull()
    const drawn = lines.slice(Number(range![1]) - 1, Number(range![2])).join('\n')
    for (const handler of ['fn list_approvals(', 'fn approve(', 'fn resolve(']) {
      expect(drawn).toContain(handler)
    }
  })
})
