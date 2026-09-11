import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import {
  agentDirs,
  EXIT_INVARIANT,
  EXIT_PROBLEMS,
  INDEX_NAME,
  main,
  MEMORY_DIR,
  MEMORY_ROOT,
  noteEntry,
  parseFrontmatter,
  readNotes,
  rebuild,
  renderIndex,
  trackedIndexFiles,
} from './agent-memory-index'

function note(name: string, description: string): string {
  return `---
name: ${name}
description: ${description}
metadata:
  type: project
---

Body text.
`
}

describe('parseFrontmatter', () => {
  test('reads top-level scalars and skips the nested metadata mapping', () => {
    const { scalars } = parseFrontmatter(note('a-note', 'what it says'))
    expect(scalars.name).toBe('a-note')
    expect(scalars.description).toBe('what it says')
    expect(scalars.type).toBeUndefined()
  })

  test('folds a wrapped description onto one line', () => {
    const { scalars } = parseFrontmatter(`---
name: wrapped
description: first half
  second half
metadata:
  type: project
---
`)
    expect(scalars.description).toBe('first half second half')
  })

  test('reads a folded or literal block scalar without its header', () => {
    // Indent and chomping indicators are legal in either order.
    for (const header of ['>', '|', '>-', '|+', '>2', '|2-', '>+2', '|-']) {
      expect(parseFrontmatter(`---
name: block
description: ${header}
  first line
  second line
metadata:
  type: project
---
`).scalars).toMatchObject({ name: 'block', description: 'first line second line' })
    }
  })

  test('reads a block scalar whose header carries a comment or trailing space', () => {
    for (const header of ['> # summary follows', '|- # summary follows', '>2 # note', '>  ', '|2-   ']) {
      expect(parseFrontmatter(`---
name: block
description: ${header}
  first line
  second line
metadata:
  type: project
---
`).scalars.description).toBe('first line second line')
    }
  })

  // YAML gives `key: # text` a null value — the remainder is a comment. Capturing
  // it made a note with no summary list as though the comment were the summary.
  test('treats a comment-only value as no value at all', () => {
    const { scalars, problems } = parseFrontmatter(`---
name: a-note
description: # write this later
metadata:
  type: project
---
`)
    expect(scalars.description).toBeUndefined()
    expect(noteEntry('n.md', `---
name: a-note
description: # write this later
metadata:
  type: project
---
`).problems).toEqual([expect.stringContaining('no `description:`')])
    expect(problems).toEqual([])
  })

  // ` #` starts a comment inside a plain scalar, so YAML reads
  // `fixed in PR #155, so do X` as `fixed in PR` — this reader keeps the line,
  // and the two disagreeing about one claim is the drift the index exists to end.
  test('reports an unquoted value whose text YAML would cut at a comment', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      'description: fixed in PR #155, so do X',
    )
    expect(parseFrontmatter(text).problems)
      .toEqual([expect.stringContaining('YAML reads as the start of a comment')])
  })

  // The fix the report asks for has to actually clear it, and `(#154)` — no space
  // before the `#` — is not a comment and must not be reported.
  test('accepts the quoted form, and a `#` with no space before it', () => {
    const quoted = [String.raw`'fixed in PR #155, so do X'`, String.raw`"fixed in PR #155, so do X"`]
    for (const value of [...quoted, 'covers (#154) fully']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([])
    }
  })

  // Inside a block scalar `#` is literal, so the report must not fire there.
  test('does not report a `#` inside a block scalar, where it is literal', () => {
    expect(parseFrontmatter(`---
name: a-note
description: >
  fixed in PR #155, so do X
metadata:
  type: project
---
`)).toMatchObject({ scalars: { description: 'fixed in PR #155, so do X' }, problems: [] })
  })

  // `description: null` is the absence of a value, not the word — storing the
  // source spelling advertised `null` as a note's summary.
  test('reports a value YAML resolves to something that is not text', () => {
    // `1e3` is a string under YAML 1.1 and the number 1000 under 1.2's core
    // schema — two readers disagreeing is reason to report, not to pick a side.
    for (const value of ['null', '~', 'true', 'no', '42', '3.14', '.inf', '1e3', '-1E3', 'y', 'N']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('rather than text')])
    }
  })

  // YAML 1.1 resolves numbers 1.2's core schema leaves as text: every digit run
  // admits `_` as a separator, and a colon-separated value is base 60, so a 1.1
  // reader makes `1_000` the number 1000 and `12:00` the number 720. Reported
  // for the reason `1e3` is — the two readers disagree about the same bytes.
  test('reports the YAML 1.1 number spellings 1.2 leaves as text', () => {
    for (const value of ['1_000', '0xDE_AD', '0b1_01', '01_7', '+1_0', '100_', '1_0.5', '12:00', '190:20:30', '12:00.5', '2026-09-12', '2026-9-1t10:00:00.5-05:00']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('rather than text')])
    }
  })

  // Only a whole plain value resolves that way: prose that merely starts with
  // one of those words is text, and a quoted one really is the string.
  // A flow sequence or mapping is valid YAML and is not a summary.
  // Verified against both readers: `description: summary: detail` is a hard
  // parse error ("mapping values are not allowed here" / "Unexpected token"),
  // so the note cannot be loaded at all — the one defect class that makes the
  // whole file unreadable rather than merely misread.
  test('reports a plain description holding a mapping separator', () => {
    for (const value of ['summary: detail', 'summary:']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('mapping')])
    }
  })

  // A colon only opens a mapping when a space or the line end follows it.
  test('leaves a colon alone where YAML does', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: ratio 3:1 and summary:detail')
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // The range guard below this one stops at 0x10FFFF, and every surrogate is
  // under it, so `\uD800` slipped through into `String.fromCodePoint` — which
  // does not throw on one. That put a lone surrogate in the index text, where
  // it cannot be encoded as UTF-8. Bun.YAML rejects the input outright.
  test('reports a double-quoted escape naming a surrogate code point', () => {
    for (const value of [String.raw`"\uD800"`, String.raw`"\U0000DFFF"`]) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('surrogate')])
    }
  })

  // An indented `#` is literal inside a block scalar and a comment after a
  // plain one — both readers give `first` here. Appending it unconditionally
  // built `first # note`, which the ` #` check then rejected: a valid note
  // failing CI on a comment YAML had already discarded.
  test('drops a comment line following a plain scalar', () => {
    const text = `---
name: a-note
description: first
  # note
metadata:
  type: project
---
`
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // The comment skip above is for *plain* scalars only. Inside a quoted one a
  // `#` is literal, and both readers fold this to `first # still text`, so
  // skipping the line there dropped real content and left the quote unclosed.
  test('keeps a # line continuing a quoted scalar', () => {
    for (const quote of ['"', '\'']) {
      const text = `---
name: a-note
description: ${quote}first
  # still text${quote}
metadata:
  type: project
---
`
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first # still text' }, problems: [] })
    }
  })

  // ...and a quoted scalar that already closed on its own line is followed by a
  // real comment, which YAML drops.
  test('drops a comment after a closed quoted scalar', () => {
    const text = `---
name: a-note
description: "done"
  # note
metadata:
  type: project
---
`
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'done' }, problems: [] })
  })

  // A comment line is dropped before it is ever measured: a tab inside one is
  // not indentation, and pyyaml loads this note as `first`.
  test('keeps a tab inside a comment following a plain scalar', () => {
    const text = `---
name: a-note
description: first
  # note\twith tab
metadata:
  type: project
---
`
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // ...but a comment line that *starts* with a tab still puts one where the
  // indentation goes, which YAML refuses.
  test('reports a comment line indented with a tab', () => {
    const text = `---
name: a-note
description: first
\t# note
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('tab')])
  })

  // `%` opens a directive, and `,`, `]`, `}` close flow collections that were
  // never opened. pyyaml refuses all four; Bun.YAML refuses `%` and disagrees
  // on the rest, which is reason to report either way.
  test('reports a description opening with a flow or directive indicator', () => {
    for (const value of ['%summary', ',summary', ']summary', '}summary']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).not.toEqual([])
    }
  })

  test('leaves those characters alone away from the head', () => {
    for (const value of ['50% faster', 'a, b', 'x] y', 'p} q']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([])
    }
  })

  // YAML separates an inline comment with a space or tab, not with any
  // whitespace JavaScript happens to recognise: both readers refuse a no-break
  // space there, while `\s` accepted it and indexed the note as valid.
  test('reports a non-ASCII space before an inline comment', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: "done"\u00A0# note')
    expect(parseFrontmatter(text).problems).not.toEqual([])
  })

  // A tab is only forbidden where indentation goes. Past the required indent of
  // a block scalar it is ordinary content, and both readers keep it.
  test('keeps a tab that falls after block indentation', () => {
    const text = `---
name: a-note
description: |
  \tfoo
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // In a plain continuation the readers disagree — pyyaml refuses the document,
  // Bun.YAML folds the tab in — which is the drift this reader reports.
  test('reports a tab inside a plain continuation', () => {
    const text = `---
name: a-note
description: first
  second\tthird
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('tab')])
  })

  // Without an explicit indicator the first content line sets the indentation,
  // and a later line under it ends the scalar where YAML expects a key.
  test('reports block content under the inferred indentation', () => {
    const text = `---
name: a-note
description: >
  first
 second
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('indent')])
  })

  test('accepts block content that holds the inferred indentation', () => {
    const text = `---
name: a-note
description: >
  first
  second
metadata:
  type: project
---
`
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first second' }, problems: [] })
  })

  // `@` and a backtick are reserved: YAML defines no meaning for them at the
  // head of a scalar, so both readers refuse the document outright.
  test('reports a description opening with a reserved indicator', () => {
    for (const value of ['@summary', '`summary`']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).not.toEqual([])
    }
  })

  test('leaves a reserved character alone away from the head', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: mail me @ home')
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // Once the quote closes, the scalar is finished: a further content line is a
  // key YAML cannot parse. A further *comment* line is still fine.
  test('reports content after a closed quoted scalar', () => {
    const text = `---
name: a-note
description: "done" # note
  junk
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).not.toEqual([])
  })

  // A tab cannot provide YAML indentation at all, so a tab-continued scalar is
  // a document neither reader will load — and this one folded it silently.
  test('reports a tab used as indentation', () => {
    const text = `---
name: a-note
description: first
\tsecond
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('tab')])
  })

  // `-` and `?` open a sequence entry and a mapping key, and `>`/`|` always
  // open a block header — none of which may carry text on the same line. Both
  // readers refuse every one of these.
  test('reports a plain description opening with a YAML indicator', () => {
    for (const value of ['- summary', '? summary', '> summary', '| summary', '>summary', '-']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).not.toEqual([])
    }
  })

  // ...and none of these is an indicator: the character is either part of a
  // number, part of a word, or simply not at the start.
  test('leaves a lookalike alone', () => {
    for (const value of ['-summary', 'a - b', 'a > b', '3 > 2 is true']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([])
    }

    // `-5` is reported, but as the number it is — not as a sequence entry.
    const negative = note('a-note', 'placeholder').replace('description: placeholder', 'description: -5')
    expect(parseFrontmatter(negative).problems).toEqual([expect.stringContaining('non-string')])
  })

  test('still accepts every valid block header', () => {
    for (const header of ['|', '>', '|2', '>-', '|+', '> # note']) {
      const text = `---
name: a-note
description: ${header}
  content here
metadata:
  type: project
---
`
      expect(parseFrontmatter(text).problems).toEqual([])
    }
  })

  // A block header may carry an explicit indentation indicator, and then the
  // content must actually meet it: both readers refuse `|2` over a line with
  // one space. The continuation branch accepted any indentation at all.
  test('reports block content under an explicit indentation indicator', () => {
    const text = `---
name: a-note
description: |2
 first
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('indentation indicator')])
  })

  test('accepts block content that meets the indicator', () => {
    const text = `---
name: a-note
description: |2
  first
metadata:
  type: project
---
`
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // The first occurrence never reached `scalars` when it had no value, so the
  // repeat check could not see it and a malformed note passed silently.
  test('reports a repeat whose first occurrence had no value', () => {
    const text = `---
name: a-note
description: # write this later
description: real
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('more than once')])
  })

  // Both readers take the last of a repeated key, so the index would not drift
  // — but the author wrote two summaries and one vanished silently, and YAML
  // requires mapping keys to be unique (js-yaml refuses the document outright).
  test('reports an indexed key given more than once', () => {
    const text = `---
name: a-note
description: first
description: second
metadata:
  type: project
---
`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('more than once')])
  })

  // Block scalar content is literal: a leading `&`, `!` or quote is text, not
  // scalar syntax, so it must not be run through the quoted-scalar reader.
  test('keeps block scalar content literal', () => {
    for (const [content, expected] of [['&notanchor', '&notanchor'], ['"not quoted"', '"not quoted"'], ['!tag', '!tag']]) {
      const text = `---
name: a-note
description: |
  ${content}
metadata:
  type: project
---
`
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: expected }, problems: [] })
    }
  })

  // Only `name` and `description` reach the index, so a top-level field that is
  // legitimately a number is not a note defect — reporting it failed `--check`
  // over a value the index never renders.
  test('ignores top-level fields the index does not read', () => {
    const text = `---
name: a-note
description: a summary
version: 2
tags: [a, b]
---
`
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  test('reports a flow collection used as a description', () => {
    for (const value of ['[summary]', '{summary: text}']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not text')])
    }
  })

  test('leaves text alone even when it opens with such a word', () => {
    for (const value of ['null and more', '42 ways to fail', String.raw`"null"`, String.raw`'42'`]) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([])
    }
  })

  test('unquotes a scalar that had to be quoted to stay valid YAML', () => {
    expect(parseFrontmatter(`---
description: "note: a colon forces quoting"
---
`).scalars.description).toBe('note: a colon forces quoting')
    expect(parseFrontmatter(`---
description: 'it''s quoted'
---
`).scalars.description).toBe('it\'s quoted')
  })

  test('returns nothing for a note with no frontmatter', () => {
    expect(parseFrontmatter('just a body\n')).toEqual({ scalars: {}, problems: [] })
  })
})

describe('noteEntry', () => {
  test('carries the frontmatter through with no problems', () => {
    const entry = noteEntry('a_note.md', note('a-note', 'what it says'))
    expect(entry).toMatchObject({ file: 'a_note.md', name: 'a-note', description: 'what it says' })
    expect(entry.problems).toEqual([])
  })

  test('falls back to the file stem and reports a note with no frontmatter', () => {
    const entry = noteEntry('orphan_note.md', 'no frontmatter here\n')
    expect(entry.name).toBe('orphan_note')
    expect(entry.problems).toHaveLength(2)
  })

  test('reports a missing description, because the index text now comes from it', () => {
    const entry = noteEntry('n.md', '---\nname: a-note\n---\n\nbody\n')
    expect(entry.problems).toEqual([
      expect.stringContaining('`description:`'),
    ])
  })
})

describe('renderIndex', () => {
  const entries = [
    noteEntry('zeta.md', note('zeta', 'last by name')),
    noteEntry('alpha.md', note('alpha', 'first by name')),
  ]

  test('emits one pointer line per note, sorted by file name', () => {
    const lines = renderIndex(entries).trimEnd().split('\n').filter(line => line.startsWith('- '))
    expect(lines).toEqual([
      '- [alpha](alpha.md) — first by name',
      '- [zeta](zeta.md) — last by name',
    ])
  })

  test('does not depend on the order the notes arrive in', () => {
    expect(renderIndex([...entries].reverse())).toBe(renderIndex(entries))
  })

  test('keeps a link resolvable when the file name carries markdown or URL meaning', () => {
    const encoded: Record<string, string> = {
      'readme).md': 'readme%29.md', // `)` would end the destination
      'a#b.md': 'a%23b.md', //        `#` would address a fragment
      'a?b.md': 'a%3Fb.md', //        `?` would start a query
      'a%2Fb.md': 'a%252Fb.md', //    an existing `%` must not read as an escape
      'review:notes.md': 'review%3Anotes.md', // `review` would read as a scheme
      'a\\b.md': 'a%5Cb.md', //        a backslash resolves as a path separator
      'a&b.md': 'a%26b.md', //         never enumerated; encoded for being unlisted
      'a😀b.md': 'a%F0%9F%98%80b.md', // one code point, four bytes — not two surrogates
      'two words.md': 'two%20words.md',
    }
    for (const [file, target] of Object.entries(encoded)) {
      expect(renderIndex([noteEntry(file, note('a-note', 'a note'))])).toContain(`](${target})`)
    }
    // An ordinary name is untouched — encoding is not applied blindly.
    expect(renderIndex([noteEntry('plain_note.md', note('a-note', 'a note'))]))
      .toContain('](plain_note.md)')
  })

  // `\s` matches past ASCII, and percent-encoding is defined over UTF-8 bytes:
  // encoding the code unit of a non-breaking space would emit `%A0`, which is
  // not the byte sequence the path is made of.
  test('encodes non-ASCII whitespace as UTF-8 bytes, not code units', () => {
    expect(renderIndex([noteEntry('a\u00A0b.md', note('a-note', 'a note'))]))
      .toContain('](a%C2%A0b.md)')
  })

  test('escapes a label that would end the link early', () => {
    expect(renderIndex([noteEntry('n.md', note('odd] name', 'a note'))]))
      .toContain('- [odd\\] name](n.md)')
  })

  test('still lists a note with no description, so nothing becomes unreachable', () => {
    const line = renderIndex([noteEntry('n.md', '---\nname: a-note\n---\n\nbody\n')])
    expect(line).toContain('- [a-note](n.md) — (no description')
  })
})

describe('rebuild', () => {
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'agent-memory-'))
    mkdirSync(join(root, 'some-agent'))
    writeFileSync(join(root, 'some-agent', 'first.md'), note('first', 'the first note'))
  })

  afterEach(() => rmSync(root, { recursive: true, force: true }))

  test('writes an index derived from the notes', () => {
    expect(rebuild(root).written).toEqual([join(root, 'some-agent', INDEX_NAME)])
    expect(readFileSync(join(root, 'some-agent', INDEX_NAME), 'utf8'))
      .toContain('- [first](first.md) — the first note')
  })

  test('is idempotent — a second run rewrites nothing', () => {
    rebuild(root)
    expect(rebuild(root).written).toEqual([])
  })

  test('replaces a hand-edited line rather than leaving the claim in two places', () => {
    const index = join(root, 'some-agent', INDEX_NAME)
    writeFileSync(index, '- [first](first.md) — a hook that drifted from the description\n')
    rebuild(root)
    const rebuilt = readFileSync(index, 'utf8')
    expect(rebuilt).toContain('- [first](first.md) — the first note')
    expect(rebuilt).not.toContain('drifted')
  })

  test('--check reports the pending rewrite without touching the file', () => {
    const { written } = rebuild(root, { check: true })
    expect(written).toEqual([join(root, 'some-agent', INDEX_NAME)])
    expect(agentDirs(root)).toEqual(['some-agent'])
    expect(readNotes(join(root, 'some-agent'))).toHaveLength(1)
    expect(() => readFileSync(join(root, 'some-agent', INDEX_NAME))).toThrow()
  })

  test('reports a note that cannot supply an index line', () => {
    writeFileSync(join(root, 'some-agent', 'broken.md'), 'no frontmatter\n')
    expect(rebuild(root, { check: true }).problems).toEqual([
      expect.stringContaining('some-agent/broken.md'),
      expect.stringContaining('some-agent/broken.md'),
    ])
  })
})

describe('trackedIndexFiles', () => {
  let repo: string

  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), 'agent-memory-repo-'))
    execFileSync('git', ['init', '-q'], { cwd: repo })
    mkdirSync(join(repo, MEMORY_ROOT, 'some-agent'), { recursive: true })
  })

  afterEach(() => rmSync(repo, { recursive: true, force: true }))

  function commit(...paths: string[]): void {
    execFileSync('git', ['add', '--', ...paths], { cwd: repo })
    execFileSync('git', [
      '-c',
      'user.email=test@example.com',
      '-c',
      'user.name=test',
      'commit',
      '-q',
      '-m',
      'add',
    ], { cwd: repo })
  }

  // The negative case below is the state the repository is meant to stay in, so
  // on its own it would pass just as happily against a function that can never
  // find anything. This is the half that shows it detects one.
  test('finds a committed index', () => {
    const index = join(MEMORY_ROOT, 'some-agent', INDEX_NAME)
    writeFileSync(join(repo, index), '- [n](n.md) — a hand-appended entry\n')
    commit(index)
    expect(trackedIndexFiles(repo)).toEqual([index])
  })

  test('ignores the notes themselves — only the index is derived', () => {
    const path = join(MEMORY_ROOT, 'some-agent', 'n.md')
    writeFileSync(join(repo, path), note('a-note', 'a note'))
    commit(path)
    expect(trackedIndexFiles(repo)).toEqual([])
  })

  // git C-quotes a path holding a non-ASCII character unless asked not to, and a
  // quoted path ends in `"` rather than `MEMORY.md` — so the suffix filter would
  // silently miss a force-tracked index and report the all-clear it never earned.
  test('finds a committed index under a non-ASCII agent directory', () => {
    mkdirSync(join(repo, MEMORY_ROOT, 'agent-mémoire'), { recursive: true })
    const index = join(MEMORY_ROOT, 'agent-mémoire', INDEX_NAME)
    writeFileSync(join(repo, index), '- [n](n.md) — a hand-appended entry\n')
    commit(index)
    expect(trackedIndexFiles(repo)).toEqual([index])
  })

  test('answers empty where git reports no repository at all', () => {
    const outside = mkdtempSync(join(tmpdir(), 'not-a-repo-'))
    try {
      expect(trackedIndexFiles(outside)).toEqual([])
    }
    finally {
      rmSync(outside, { recursive: true, force: true })
    }
  })

  // The other way to have no work tree, and it is not the failure branch above:
  // `ls-files` succeeds in a bare repository and simply lists nothing, so the
  // `[]` here is an answered question rather than a swallowed error.
  test('answers empty in a bare repository, via the success path', () => {
    const bare = mkdtempSync(join(tmpdir(), 'bare-repo-'))
    try {
      execFileSync('git', ['init', '-q', '--bare'], { cwd: bare })
      expect(trackedIndexFiles(bare)).toEqual([])
    }
    finally {
      rmSync(bare, { recursive: true, force: true })
    }
  })
})

describe('main', () => {
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'agent-memory-main-'))
    mkdirSync(join(root, 'some-agent'))
  })

  afterEach(() => rmSync(root, { recursive: true, force: true }))

  test('exits 0 and writes when every note can supply a line', () => {
    writeFileSync(join(root, 'some-agent', 'first.md'), note('first', 'the first note'))
    expect(main([], root, root)).toBe(0)
    expect(readFileSync(join(root, 'some-agent', INDEX_NAME), 'utf8')).toContain('- [first](first.md)')
  })

  // EXIT_PROBLEMS, not 1: a caller that tolerates a malformed note must still
  // abort when the script could not run at all, and an uncaught throw exits 1.
  test('exits EXIT_PROBLEMS when a note cannot supply a line', () => {
    writeFileSync(join(root, 'some-agent', 'broken.md'), 'no frontmatter\n')
    expect(main([], root, root)).toBe(EXIT_PROBLEMS)
    expect(EXIT_PROBLEMS).not.toBe(1)
  })

  // The tracked-index invariant is broken here, so the run has to stop with the
  // tree exactly as it found it — reporting after writing is reporting too late.
  test('refuses a tracked index without writing anything', () => {
    const repo = mkdtempSync(join(tmpdir(), 'agent-memory-tracked-'))
    try {
      execFileSync('git', ['init', '-q'], { cwd: repo })
      const dir = join(repo, MEMORY_ROOT, 'some-agent')
      mkdirSync(dir, { recursive: true })
      const index = join(MEMORY_ROOT, 'some-agent', INDEX_NAME)
      writeFileSync(join(repo, index), 'stale hand-written index\n')
      writeFileSync(join(dir, 'first.md'), note('first', 'the first note'))
      execFileSync('git', ['add', '--', index], { cwd: repo })
      execFileSync('git', [
        '-c',
        'user.email=test@example.com',
        '-c',
        'user.name=test',
        'commit',
        '-q',
        '-m',
        'add',
      ], { cwd: repo })

      // EXIT_INVARIANT, not EXIT_PROBLEMS: this path writes nothing, so a caller
      // that carries on from a malformed note must not carry on from this and
      // call what it has an index.
      expect(main([], join(repo, MEMORY_ROOT), repo)).toBe(EXIT_INVARIANT)
      expect(EXIT_INVARIANT).not.toBe(EXIT_PROBLEMS)
      expect(readFileSync(join(repo, index), 'utf8')).toBe('stale hand-written index\n')
    }
    finally {
      rmSync(repo, { recursive: true, force: true })
    }
  })

  test('--check exits 0 without writing', () => {
    writeFileSync(join(root, 'some-agent', 'first.md'), note('first', 'the first note'))
    expect(main(['--check'], root, root)).toBe(0)
    expect(() => readFileSync(join(root, 'some-agent', INDEX_NAME))).toThrow()
  })
})

describe('this repository', () => {
  // The regression guard for issue #129. A tracked index is a file every
  // concurrent PR appends to, and the conflict hunk does not show the union
  // that is the only correct resolution — so re-tracking one silently
  // reintroduces both the conflicts and the risk of dropping someone's entry.
  test('tracks no generated MEMORY.md index', () => {
    expect(trackedIndexFiles()).toEqual([])
  })

  // Reachability: the index is now derived, so a note whose frontmatter cannot
  // supply a line is a note future agents will not be pointed at.
  test('every committed note can supply its own index line', () => {
    expect(rebuild(MEMORY_DIR, { check: true }).problems).toEqual([])
  })
})

describe('parseFrontmatter — quoted scalars', () => {
  // Unescaping only `\"` and `\\` left a literal `\n` in the index where the
  // note's own frontmatter said a line break.
  test('decodes the escapes of a double-quoted description', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "a\tb: \"quoted\", caf\u00E9, back\\slash"`,
    )
    // The tab decodes and is then folded with every other whitespace run, which
    // is what keeps an entry to one line; the point here is that it decoded.
    expect(parseFrontmatter(text).scalars.description).toBe('a b: "quoted", café, back\\slash')
  })

  // YAML writes hex escapes in either case; only accepting A-F left `caf\u00e9`
  // in the index as the eight characters the note had typed.
  test('decodes hex escapes written in lower case', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "caf\u00e9 \x0a caf\u00E9"`,
    )
    expect(parseFrontmatter(text).scalars.description).toBe('café café')
  })

  // `\U` admits eight digits, so it can name something that is not a code
  // point. That is a note to report, not a crash that takes every note with it.
  test('leaves an out-of-range code point alone instead of throwing', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "over \UFFFFFFFF the end"`,
    )
    expect(() => parseFrontmatter(text)).not.toThrow()
    const { scalars, problems } = parseFrontmatter(text)
    // The text is kept — a guess would be worse — but the note is flagged, so
    // the difference between this reader and the one that loads the note into
    // an agent's context cannot pass CI unnoticed.
    expect(scalars.description).toBe(String.raw`over \UFFFFFFFF the end`)
    expect(problems).toEqual([expect.stringContaining(String.raw`\UFFFFFFFF`)])
  })

  // An escape YAML does not define is invalid YAML, not something to guess at.
  test('leaves an undefined escape exactly as written', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "a\qb"`,
    )
    const { scalars, problems } = parseFrontmatter(text)
    expect(scalars.description).toBe(String.raw`a\qb`)
    expect(problems).toEqual([expect.stringContaining(String.raw`\q`)])
  })

  // A quote that never closes is not a plain scalar — the note's YAML does not
  // parse at all, so listing it as though it were fine hides that.
  test('reports a quoted scalar that never closes', () => {
    // The third and fourth end with a quote character that closes nothing: it
    // is escaped. `endsWith` cannot tell those from a terminator.
    for (const broken of ['"unfinished', '\'unfinished', String.raw`"unfinished \"`, '"', String.raw`"a\"`]) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${broken}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('never closes it')])
    }
  })

  // One callback carried two unrelated problem kinds, and only one of them
  // passed a bare token: the other passed a whole sentence, which the caller
  // then wrapped in "is double-quoted and holds `…`". So an unterminated
  // single quote and a plain `&anchor` were both reported as double-quoted,
  // each with a complete report nested inside another one.
  test('describes a malformed scalar as the kind it actually is', () => {
    const report = (value: string): string =>
      parseFrontmatter(`---
name: a-note
description: ${value}
metadata:
  type: project
---
`).problems[0] ?? ''

    expect(report(String.raw`"holds \q here`.concat('"'))).toContain('is double-quoted and holds')
    expect(report('&anchor')).toContain('anchor indicator')
    expect(report(String.raw`'unclosed`)).toContain('never closes it')

    // None of the others is double-quoted, and none nests a second report.
    for (const value of [String.raw`"unclosed`, String.raw`'unclosed`, '&anchor', '*alias', '!tag']) {
      expect(report(value)).not.toContain('is double-quoted and holds')
      expect(report(value)).not.toContain('which YAML does not define')
    }
  })

  // Valid YAML: the comment is outside the quotes. Rejecting it would fail a
  // note that loads perfectly well — and `#` inside the quotes stays literal,
  // which is what these descriptions are full of.
  test('accepts a quoted scalar followed by an inline comment', () => {
    const withComment = (value: string): string =>
      note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)

    expect(parseFrontmatter(withComment('"the text" # a trailing note')).scalars.description)
      .toBe('the text')
    expect(parseFrontmatter(withComment('\'the text\' # a trailing note')).scalars.description)
      .toBe('the text')
    expect(parseFrontmatter(withComment('"see #129 for why" # a trailing note')).scalars.description)
      .toBe('see #129 for why')
    expect(parseFrontmatter(withComment('"the text" # a trailing note')).problems).toEqual([])
  })

  // `&`, `*` and `!` cannot begin a plain scalar, so a value starting with one
  // is a decoration this reader does not resolve — and keeping it would put the
  // decoration in the index where the note's value is the text after it.
  test('reports an anchor, alias or tag instead of indexing the decoration', () => {
    const cases: Record<string, string> = {
      '&summary concrete summary': 'anchor',
      '*summary': 'alias',
      '!!str concrete summary': 'tag',
    }
    for (const [value, name] of Object.entries(cases)) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining(name)])
    }
  })

  // YAML drops an escaped line break *and* the indentation after it, where
  // every other continuation joins with a space.
  test('joins an escaped line break with nothing, not a space', () => {
    const { scalars, problems } = parseFrontmatter(`---
name: a-note
description: "one\\
  two"
metadata:
  type: project
---
`)
    expect(scalars.description).toBe('onetwo')
    expect(problems).toEqual([])
  })

  // A trailing `\\` is an escaped backslash, not an escaped break, so that line
  // folds with a space like any other.
  test('still folds with a space after an escaped backslash', () => {
    const { scalars } = parseFrontmatter(`---
name: a-note
description: "one\\\\
  two"
metadata:
  type: project
---
`)
    expect(scalars.description).toBe('one\\ two')
  })

  // A note whose frontmatter this reader and the real one may read differently
  // has to fail the gate, not list with text neither of them agreed on.
  test('an undefined escape makes the note fail --check', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "a\qb"`,
    )
    expect(noteEntry('n.md', text).problems).toEqual([expect.stringContaining(String.raw`\q`)])
  })
})

describe('noteEntry — one line per entry', () => {
  // An index entry is one line of a markdown list. A decoded `\n` would split
  // the item and orphan everything after it, so the flattening is structural.
  test('flattens a description that decodes to more than one line', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "first\nsecond   third"`,
    )
    expect(noteEntry('n.md', text).description).toBe('first second third')
    expect(renderIndex([noteEntry('n.md', text)]).split('\n').filter(l => l.startsWith('- '))).toHaveLength(1)
  })
})

describe('rebuild — the index file itself', () => {
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'agent-memory-symlink-'))
    mkdirSync(join(root, 'some-agent'))
    writeFileSync(join(root, 'some-agent', 'n.md'), note('a-note', 'a note'))
  })

  afterEach(() => rmSync(root, { recursive: true, force: true }))

  // `writeFileSync` follows a symlink, so an ordinary rebuild would overwrite
  // whatever a force-added index pointed at — before any other check runs.
  const refusal = `some-agent/${INDEX_NAME}: is a symlink; an index is generated in place, refusing to write through it`

  test('refuses to write an index through a symlink, leaving the target intact', () => {
    const target = join(root, 'private.txt')
    writeFileSync(target, 'not an index\n')
    symlinkSync(target, join(root, 'some-agent', INDEX_NAME))

    const { written, problems, refusals } = rebuild(root)

    expect(readFileSync(target, 'utf8')).toBe('not an index\n')
    expect(written).toEqual([])
    expect(problems).toEqual([])
    expect(refusals).toEqual([refusal])
  })

  // `existsSync` follows the link and answers false here, so a guard built on it
  // would fall through and *create* the target it was meant to protect.
  test('refuses a dangling symlink rather than creating its target', () => {
    const target = join(root, 'absent.txt')
    symlinkSync(target, join(root, 'some-agent', INDEX_NAME))

    const { written, refusals } = rebuild(root)

    expect(existsSync(target)).toBe(false)
    expect(written).toEqual([])
    expect(refusals).toEqual([refusal])
  })

  // Reported even when nothing would be written: a symlinked index is a broken
  // invariant whether or not its target happens to hold the right bytes today.
  test('reports a symlink whose target already matches the rendered index', () => {
    const target = join(root, 'match.txt')
    writeFileSync(target, renderIndex(readNotes(join(root, 'some-agent'))))
    symlinkSync(target, join(root, 'some-agent', INDEX_NAME))

    expect(rebuild(root).refusals).toEqual([refusal])
  })

  // "Nothing was written" has to hold across the whole run, not per agent: the
  // refusal was found on the second agent, and the first must not already be on
  // disk by then.
  test('writes no index at all when any agent refuses', () => {
    mkdirSync(join(root, 'z-agent'))
    writeFileSync(join(root, 'z-agent', 'n.md'), note('a-note', 'a note'))
    symlinkSync(join(root, 'elsewhere.txt'), join(root, 'z-agent', INDEX_NAME))

    const { written } = rebuild(root)

    expect(written).toEqual([])
    expect(existsSync(join(root, 'some-agent', INDEX_NAME))).toBe(false)
  })

  // A refusal must not also silence the note defects: the next run would fail
  // on them too, and one invocation should name everything it found.
  test('reports a malformed note alongside a refusal', () => {
    writeFileSync(join(root, 'some-agent', 'broken.md'), 'no frontmatter\n')
    mkdirSync(join(root, 'z-agent'))
    symlinkSync(join(root, 'elsewhere.txt'), join(root, 'z-agent', INDEX_NAME))

    const { problems, refusals } = rebuild(root)

    expect(refusals).toHaveLength(1)
    expect(problems).toEqual([
      expect.stringContaining('broken.md'),
      expect.stringContaining('broken.md'),
    ])
  })

  // A refusal means this agent has no index at all, so it cannot come back as
  // the code a caller is allowed to carry on from.
  test('exits EXIT_INVARIANT, not EXIT_PROBLEMS, when an index is refused', () => {
    symlinkSync(join(root, 'elsewhere.txt'), join(root, 'some-agent', INDEX_NAME))
    expect(main([], root, root)).toBe(EXIT_INVARIANT)
  })
})
