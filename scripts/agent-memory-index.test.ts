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
    const entry = noteEntry('n.md', '---\nname: n\n---\n\nbody\n')
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
      expect(renderIndex([noteEntry(file, note('n', 'a note'))])).toContain(`](${target})`)
    }
    // An ordinary name is untouched — encoding is not applied blindly.
    expect(renderIndex([noteEntry('plain_note.md', note('n', 'a note'))]))
      .toContain('](plain_note.md)')
  })

  // `\s` matches past ASCII, and percent-encoding is defined over UTF-8 bytes:
  // encoding the code unit of a non-breaking space would emit `%A0`, which is
  // not the byte sequence the path is made of.
  test('encodes non-ASCII whitespace as UTF-8 bytes, not code units', () => {
    expect(renderIndex([noteEntry('a\u00A0b.md', note('n', 'a note'))]))
      .toContain('](a%C2%A0b.md)')
  })

  test('escapes a label that would end the link early', () => {
    expect(renderIndex([noteEntry('n.md', note('odd] name', 'a note'))]))
      .toContain('- [odd\\] name](n.md)')
  })

  test('still lists a note with no description, so nothing becomes unreachable', () => {
    const line = renderIndex([noteEntry('n.md', '---\nname: n\n---\n\nbody\n')])
    expect(line).toContain('- [n](n.md) — (no description')
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
    writeFileSync(join(repo, path), note('n', 'a note'))
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

  test('answers empty outside a work tree, where there is nothing to assert', () => {
    const bare = mkdtempSync(join(tmpdir(), 'not-a-repo-'))
    try {
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
    const text = note('n', 'placeholder').replace(
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
    const text = note('n', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "caf\u00e9 \x0a caf\u00E9"`,
    )
    expect(parseFrontmatter(text).scalars.description).toBe('café café')
  })

  // `\U` admits eight digits, so it can name something that is not a code
  // point. That is a note to report, not a crash that takes every note with it.
  test('leaves an out-of-range code point alone instead of throwing', () => {
    const text = note('n', 'placeholder').replace(
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
    const text = note('n', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "a\qb"`,
    )
    const { scalars, problems } = parseFrontmatter(text)
    expect(scalars.description).toBe(String.raw`a\qb`)
    expect(problems).toEqual([expect.stringContaining(String.raw`\q`)])
  })

  // A note whose frontmatter this reader and the real one may read differently
  // has to fail the gate, not list with text neither of them agreed on.
  test('an undefined escape makes the note fail --check', () => {
    const text = note('n', 'placeholder').replace(
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
    const text = note('n', 'placeholder').replace(
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
    writeFileSync(join(root, 'some-agent', 'n.md'), note('n', 'a note'))
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
    writeFileSync(join(root, 'z-agent', 'n.md'), note('n', 'a note'))
    symlinkSync(join(root, 'elsewhere.txt'), join(root, 'z-agent', INDEX_NAME))

    const { written } = rebuild(root)

    expect(written).toEqual([])
    expect(existsSync(join(root, 'some-agent', INDEX_NAME))).toBe(false)
  })

  // A refusal means this agent has no index at all, so it cannot come back as
  // the code a caller is allowed to carry on from.
  test('exits EXIT_INVARIANT, not EXIT_PROBLEMS, when an index is refused', () => {
    symlinkSync(join(root, 'elsewhere.txt'), join(root, 'some-agent', INDEX_NAME))
    expect(main([], root, root)).toBe(EXIT_INVARIANT)
  })
})
