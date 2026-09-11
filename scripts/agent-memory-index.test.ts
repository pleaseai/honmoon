import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import {
  agentDirs,
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
    const scalars = parseFrontmatter(note('a-note', 'what it says'))
    expect(scalars.name).toBe('a-note')
    expect(scalars.description).toBe('what it says')
    expect(scalars.type).toBeUndefined()
  })

  test('folds a wrapped description onto one line', () => {
    const scalars = parseFrontmatter(`---
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
`)).toMatchObject({ name: 'block', description: 'first line second line' })
    }
  })

  test('unquotes a scalar that had to be quoted to stay valid YAML', () => {
    expect(parseFrontmatter(`---
description: "note: a colon forces quoting"
---
`).description).toBe('note: a colon forces quoting')
    expect(parseFrontmatter(`---
description: 'it''s quoted'
---
`).description).toBe('it\'s quoted')
  })

  test('returns nothing for a note with no frontmatter', () => {
    expect(parseFrontmatter('just a body\n')).toEqual({})
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
      'two words.md': 'two%20words.md',
    }
    for (const [file, target] of Object.entries(encoded)) {
      expect(renderIndex([noteEntry(file, note('n', 'a note'))])).toContain(`](${target})`)
    }
    // An ordinary name is untouched — encoding is not applied blindly.
    expect(renderIndex([noteEntry('plain_note.md', note('n', 'a note'))]))
      .toContain('](plain_note.md)')
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

  test('exits 1 when a note cannot supply a line', () => {
    writeFileSync(join(root, 'some-agent', 'broken.md'), 'no frontmatter\n')
    expect(main([], root, root)).toBe(1)
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
