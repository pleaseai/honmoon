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

/**
 * A note whose `description:` is written out verbatim, for the multi-line and
 * indicator-led values `note()` cannot express — the continuation lines are
 * part of the argument.
 */
function noteWith(description: string, tail = 'metadata:\n  type: project'): string {
  return `---\nname: a-note\ndescription: ${description}${tail ? `\n${tail}` : ''}\n---\n`
}

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
    const { scalars, problems } = parseFrontmatter(noteWith(`# write this later`))
    expect(scalars.description).toBeUndefined()
    expect(noteEntry('n.md', noteWith(`# write this later`)).problems).toEqual([expect.stringContaining('no `description:`')])
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

  // The comment text is written under no grammar, so unmasking its `#` can put
  // YAML syntax into the line. A `: ` in it reads as a nested mapping key and
  // the probe stops parsing — on the very line it was asked about, which is the
  // one refusal the probe may not answer "nothing here" to. Masking the line's
  // remaining `:` alongside the `#` keeps it a plain scalar.
  test('reports a cut whose comment text holds a colon', () => {
    for (const value of ['fixed in PR #155: see docs', 'note #1: do X, not Y', 'see #12: and #13: too']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems)
        .toEqual([expect.stringContaining('YAML reads as the start of a comment')])
    }
  })

  // The stand-ins are put back before the comparison, so a `:` that is genuinely
  // part of a quoted value is compared as itself and reports nothing.
  test('accepts a quoted value holding both a `#` and a colon', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "quoted #155: still text"`,
    )
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'quoted #155: still text' },
      problems: [],
    })
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
    expect(parseFrontmatter(noteWith(`>
  fixed in PR #155, so do X`))).toMatchObject({ scalars: { description: 'fixed in PR #155, so do X' }, problems: [] })
  })

  // The cut can happen on a *continuation* line as easily as on the key's own,
  // and the probe finds it there for the same reason it finds anything: it
  // masks one `#` and reads the block again, rather than holding a rule about
  // which lines a plain scalar may span.
  test('reports a value cut at a comment on a continuation line', () => {
    const text = noteWith(`one
  two #3 four`)
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'one two' },
      problems: [expect.stringContaining('YAML reads as the start of a comment')],
    })
  })

  // A comment that follows a *closed* quoted scalar is valid, and masking its
  // `#` makes the document stop parsing — which says nothing about that comment
  // and must not be reported. It must also not swallow a real cut on another
  // line, which is why one `#` is masked at a time rather than all of them.
  // The refusal class the probe skips is a comment after a *closed node*, and a
  // flow collection is one as much as a quoted scalar is. Nothing was cut from
  // either — the quoted value comes back whole, and the collection is reported
  // as not-text by the caller — so the skip costs no report in either case.
  test('skips the probe after a closed flow collection, which loses no report', () => {
    const withValue = (value: string): string =>
      note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)

    expect(parseFrontmatter(withValue('[a, b] # a trailing note')).problems)
      .toEqual([expect.stringContaining('is a sequence rather than text')])
    expect(parseFrontmatter(withValue('{a: b} # a trailing note')).problems)
      .toEqual([expect.stringContaining('is a mapping rather than text')])
    expect(parseFrontmatter(withValue(`'single' # a trailing note`)))
      .toMatchObject({ scalars: { description: 'single' }, problems: [] })
  })

  test('still reports a cut key when another line ends in a valid comment', () => {
    const text = `---\nname: cut at #1 here\ndescription: "quoted" # a real comment\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { name: 'cut at', description: 'quoted' },
      problems: [expect.stringContaining('`name:` is unquoted')],
    })
  })

  // The stand-ins are searched for in the source *and* in what it resolves to,
  // because those differ. `"quoted  # still text"` holds no private-use
  // character as text and holds one after the escape is decoded; a stand-in
  // chosen from the source alone would be rewritten by the restore step along
  // with the mask, and this correctly quoted value would be reported as cut.
  test('does not report a quoted value whose escape decodes to a probe character', () => {
    const text = `---\nname: a-note\ndescription: "quoted \\uE000 # still text"\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'quoted \u{E000} # still text' },
      problems: [],
    })
  })

  // Running out of stand-ins is only a problem when there is a `#` to mask. A
  // note with none is owed no report about the reader's ability to probe one.
  test('says nothing about exhausted probes when there is no comment to check', () => {
    let every = ''
    for (let point = 0xE000; point <= 0xF8FF; point++) {
      every += String.fromCodePoint(point)
    }
    expect(parseFrontmatter(`---\nname: a-note\ndescription: "${every}"\n---\n`).problems).toEqual([])
  })

  // The probe stands private-use code points in for the characters it masks.
  // They are searched for in the note rather than fixed, so a note that happens
  // to hold one is still probed — a stand-in that collided would have turned the
  // check off, and a note's own content must not be able to do that.
  test('probes a note that already holds a private-use character', () => {
    const text = noteWith('holds \u{E000} and a cut at #1')
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'holds \u{E000} and a cut at' },
      problems: [expect.stringContaining('YAML reads as the start of a comment')],
    })
  })

  // `description: 42` is an integer and `description: [a]` a sequence — valid
  // YAML, and not a summary. Publishing the source spelling as the index text
  // advertised a description the frontmatter does not yield.
  test('reports a value YAML resolves to something that is not text', () => {
    // `.inf` is `Infinity`, which is the reason the report renders the value
    // with `String` and not `JSON.stringify` — JSON has no spelling for it and
    // would name the value `null`.
    for (const value of ['true', '42', '3.14', '.inf', '1e3', '-1E3', '0644']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('rather than text')])
    }
    expect(parseFrontmatter(note('a-note', '.inf')).problems)
      .toEqual([expect.stringContaining('`Infinity`')])
  })

  // Every spelling of nothing resolves to the same thing, and a parser cannot
  // tell them apart: `~`, `null` and the comment-only value the test above
  // covers are one value — the absence of one. So the report is the one they
  // share, and it is `noteEntry`'s: the note has no summary. The scanner this
  // replaced called `description: null` a non-string and `description: # todo`
  // no value at all, which was two reports for one state of the document (#168).
  test('treats every spelling of a null description as no description', () => {
    for (const value of ['null', 'Null', 'NULL', '~']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).scalars.description).toBeUndefined()
      expect(parseFrontmatter(text).problems).toEqual([])
      expect(noteEntry('n.md', text).problems).toEqual([expect.stringContaining('no `description:`')])
    }
  })

  // Dropped with the scanner (#168), deliberately. These spellings are numbers
  // to a YAML 1.1 reader (pyyaml) and text to a 1.2 one, and `Bun.YAML` is a
  // 1.2 reader — it resolves each to exactly the text the index publishes, so
  // there is no longer a disagreement between this reader and the value.
  //
  // Reporting them again would need this file to decide from the *source*
  // whether the value was written plain, because a quoted `"12:00"` is text to
  // every reader. That decision is the scanner, and the scanner is what thirty
  // one review rounds could not finish enumerating. What is guarded instead is
  // the case that survives every reader: a value this parser resolves to
  // something that is not text, in the test above.
  test('leaves the YAML 1.1 number spellings 1.2 resolves as text alone', () => {
    for (const value of ['1_000', '0xDE_AD', '0b1_01', '01_7', '+1_0', '100_', '1_0.5', '12:00', '190:20:30', '12:00.5', '2026-09-12', '2026-9-1t10:00:00.5-05:00']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: value }, problems: [] })
    }
  })

  // The same call, for the YAML 1.1 booleans 1.2 leaves as text.
  test('leaves the YAML 1.1 boolean spellings 1.2 resolves as text alone', () => {
    for (const value of ['yes', 'no', 'on', 'off', 'y', 'N']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: value }, problems: [] })
    }
  })

  // Only a whole plain value resolves that way: prose that merely starts with
  // one of those words is text, and a quoted one really is the string.
  // A flow sequence or mapping is valid YAML and is not a summary.
  // `description: summary: detail` is a hard parse error to every reader
  // ("mapping values are not allowed here" / "Unexpected token"), so the note
  // cannot be loaded at all — the one defect class that makes the whole file
  // unreadable rather than merely misread. The parser is the one that says so
  // now, which is why the report is the refusal and not a sentence about
  // mappings written here (#168).
  test('reports a plain description holding a mapping separator', () => {
    for (const value of ['summary: detail', 'summary:']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
    }
  })

  // A colon only opens a mapping when a space or the line end follows it.
  test('leaves a colon alone where YAML does', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: ratio 3:1 and summary:detail')
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // A lone surrogate is not a character: it cannot be encoded as UTF-8, so
  // writing one to the index yields a replacement character. The scanner had to
  // be taught that its own 0x10FFFF range guard let every surrogate through;
  // `Bun.YAML` rejects the escape outright, which is the whole class of
  // "an escape this reader resolves and a real one refuses" settled at once.
  test('reports a double-quoted escape naming a surrogate code point', () => {
    for (const value of [String.raw`"\uD800"`, String.raw`"\U0000DFFF"`]) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
    }
  })

  // An indented `#` is literal inside a block scalar and a comment after a
  // plain one — both readers give `first` here. Appending it unconditionally
  // built `first # note`, which the ` #` check then rejected: a valid note
  // failing CI on a comment YAML had already discarded.
  test('drops a comment line following a plain scalar', () => {
    const text = noteWith(`first
  # note`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // The comment skip above is for *plain* scalars only. Inside a quoted one a
  // `#` is literal, and both readers fold this to `first # still text`, so
  // skipping the line there dropped real content and left the quote unclosed.
  test('keeps a # line continuing a quoted scalar', () => {
    for (const quote of ['"', '\'']) {
      const text = noteWith(`${quote}first
  # still text${quote}`)
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first # still text' }, problems: [] })
    }
  })

  // ...and a quoted scalar that already closed on its own line is followed by a
  // real comment, which YAML drops.
  test('drops a comment after a closed quoted scalar', () => {
    const text = noteWith(`"done"
  # note`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'done' }, problems: [] })
  })

  // A no-break space is content wherever it sits. A leading one used to make
  // the value vanish outright — the key matched with no value at all — so the
  // note was reported as having no description.
  test('keeps a literal no-break space at either edge', () => {
    const nbsp = '\u00A0'
    expect(parseFrontmatter(noteWith(`${nbsp}text`)).scalars.description).toBe(`${nbsp}text`)
    expect(parseFrontmatter(noteWith(`text${nbsp}`)).scalars.description).toBe(`text${nbsp}`)
  })

  // A frontmatter mapping may be indented as a whole, as long as its keys agree.
  // Matching only at column zero reported both keys missing for a valid note.
  test('reads a root mapping that is indented as a whole', () => {
    const text = '---\n  name: a-note\n  description: useful summary\n  metadata:\n    type: project\n---\n'
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { name: 'a-note', description: 'useful summary' },
      problems: [],
    })
  })

  // ...and the nested mapping is still nested, not a second pair of root keys.
  test('does not mistake a deeper mapping for a root key', () => {
    const text = '---\n  name: a-note\n  description: useful summary\n  metadata:\n    type: project\n---\n'
    expect(parseFrontmatter(text).scalars.type).toBeUndefined()
  })

  // The root indentation comes from the mapping's first content line, not from
  // the first line that happens to look like an indexable key. An outer key
  // `TOP_LEVEL_KEY` cannot spell — a dot puts it out of reach — used to leave
  // the root undecided, so its *members* claimed the root and the index
  // published a nested summary as the note's own.
  test('does not read a nested mapping as the root one', () => {
    const text = '---\nmy.key:\n  name: nested\n  description: nested summary\n---\n'
    expect(parseFrontmatter(text).scalars.description).toBeUndefined()
  })

  // A tab never indents in YAML, so a mapping indented with one is a document
  // no reader will load. Measuring the tab as a width accepted it; the parser
  // refuses it and says so in as many words.
  test('reports a root mapping indented with a tab', () => {
    const text = '---\n\tname: a-note\n\tdescription: summary\n---\n'
    expect(parseFrontmatter(text).problems)
      .toEqual([expect.stringContaining('Tab characters cannot be used as indentation')])
  })

  // An outdented comment ends a block scalar the same way a column-zero one
  // does, so the content after it lands where a key belongs and the note does
  // not load at all.
  test('reports block content that resumes after an outdented comment', () => {
    const text = '---\nname: a-note\ndescription: >\n  first\n # note\n  second\n---\n'
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
  })

  // ...but only *content* resumes. A second comment after the one that ended
  // the value is still a comment, and pyyaml loads the note.
  test('accepts a comment after the one that ended the value', () => {
    for (const after of [' # b', '  # b']) {
      const text = `---\nname: a-note\ndescription: >\n  first\n # a\n${after}\n---\n`
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
    }
  })

  // A no-break space is not indentation and not a separator, so a line opening
  // on one is content where a key belongs, and the document does not load.
  // Deciding this with `String.prototype.trim` read that line as a comment.
  test('does not read a no-break space before a hash as a comment', () => {
    const text = `---\nname: a-note\ndescription: summary\n\u00A0# note\n---\n`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
  })

  // The same class on a continuation line, where trimming it edited the value:
  // pyyaml keeps the no-break space at either edge of a folded line.
  test('keeps a no-break space at the edge of a continuation line', () => {
    const lead = `---\nname: a-note\ndescription: summary\n  \u00A0more\n---\n`
    const trail = `---\nname: a-note\ndescription: summary\n  more\u00A0\n---\n`
    expect(parseFrontmatter(lead).scalars.description).toBe('summary \u00A0more')
    expect(parseFrontmatter(trail).scalars.description).toBe('summary more\u00A0')
  })

  // An explicit indicator counts from the mapping's own indentation, not from
  // column zero: under a mapping indented by two, `|2` requires four spaces.
  // A reader refuses three and accepts four. Counting the indicator from column
  // zero was a defect the scanner needed a review round to find; the parser has
  // never needed telling where the mapping starts.
  test('counts an explicit block indicator from the root indentation', () => {
    const short = '---\n  name: a-note\n  description: |2\n   text\n---\n'
    const met = '---\n  name: a-note\n  description: |2\n    text\n---\n'
    expect(parseFrontmatter(short).problems).toEqual([expect.stringContaining('not valid YAML')])
    expect(parseFrontmatter(met)).toMatchObject({ scalars: { description: 'text' }, problems: [] })
  })

  // Only a double-quoted scalar uses a trailing backslash to escape the break.
  // In a plain or single-quoted one it is literal text, and dropping it edited
  // the summary.
  test('keeps a literal trailing backslash in an unquoted scalar', () => {
    const text = '---\nname: a-note\ndescription: ends with a backslash \\\n\n  more\n---\n'
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'ends with a backslash \\ more' }, problems: [] })
  })

  // The index is one line, so whitespace that would break it is collapsed —
  // but a no-break space is content. Flattening it made the index text differ
  // from the value the note's frontmatter yields.
  test('keeps a no-break space, however it was written', () => {
    const nbsp = '\u00A0'
    for (const written of [`one${nbsp}two`, String.raw`"one\_two"`]) {
      const got = parseFrontmatter(noteWith(written)).scalars.description ?? ''
      expect([...got].map(c => c.charCodeAt(0))).toEqual([111, 110, 101, 0xA0, 116, 119, 111])
    }
  })

  test('keeps a no-break space at the edges, which trim would have eaten', () => {
    const got = parseFrontmatter(noteWith(String.raw`"\_padded\_"`)).scalars.description ?? ''
    expect(got).toBe('\u00A0padded\u00A0')
  })

  // ...while every whitespace that really would break the line still collapses.
  test('still folds line-breaking whitespace onto one line', () => {
    const got = parseFrontmatter(noteWith(String.raw`"a\nb\tc\Ld\Pe\Nf"`)).scalars.description
    expect(got).toBe('a b c d e f')
  })

  // An escaped line break joins with nothing, but only to the line that follows
  // it. A blank line in between is itself a break, so both readers resolve this
  // to `one\ntwo` — which the one-line index renders as `one two`, not `onetwo`.
  test('keeps the break a blank line puts back after an escaped continuation', () => {
    const text = '---\nname: a-note\ndescription: "one\\\n\n  two"\n---\n'
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'one two' }, problems: [] })
  })

  // ...while the direct continuation still joins with nothing, as both readers do.
  test('joins an escaped continuation with nothing when no blank line intervenes', () => {
    const text = '---\nname: a-note\ndescription: "one\\\n  two"\n---\n'
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'onetwo' }, problems: [] })
  })

  // A key-shaped line at column zero ends the value above it, whether or not
  // this index reads that key — otherwise its wrapped value folds into the
  // previous one and the index renders text the note never put there.
  test('does not fold a non-indexed key\'s wrapped value into the previous key', () => {
    const text = '---\nname: a-note\ndescription: a summary\nfoo.bar: first\n  second\n---\n'
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'a summary' }, problems: [] })
  })

  // A comment at column zero ends the value above it, so indented content after
  // one lands where YAML expects a key. Both readers refuse it, for a block
  // scalar and a plain one alike.
  test('reports content resumed after a column-zero comment', () => {
    for (const opening of ['>', 'first']) {
      expect(parseFrontmatter(noteWith(`${opening}\n# comment\n  actual`, '')).problems)
        .toEqual([expect.stringContaining('not valid YAML')])
    }
  })

  // ...but a column-zero comment that simply precedes the next key is fine, and
  // an *indented* comment under a block scalar is its content, not a comment.
  test('accepts a column-zero comment that ends the value cleanly', () => {
    expect(parseFrontmatter(noteWith('>\n# comment', 'metadata:\n  type: project')).problems).toEqual([])
  })

  // The unkeyed-line check must not decide what a *key* looks like. Plenty of
  // valid keys fall outside the narrow pattern this file matches for `name` and
  // `description`, and reporting them failed CI for notes that load fine.
  test('leaves a valid top-level key it does not index alone', () => {
    for (const line of ['foo.bar: x', '2fa: x', '"odd key": x', 'UPPER: x']) {
      const text = noteWith('a summary', line)
      expect(parseFrontmatter(text).problems).toEqual([])
    }
  })

  // `...` ends a YAML document explicitly and may precede the closing fence.
  test('accepts an explicit document end marker', () => {
    const text = noteWith('a summary', '...')
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // A comment indented under a block scalar's content ends the scalar, and YAML
  // ignores it — folding it in both corrupted the summary and failed the note.
  test('ignores a comment outdented below block content', () => {
    const text = noteWith('>\n  first\n # note', '')
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // ...while outdented *content* is still the parse error it was.
  test('still reports outdented block content', () => {
    const text = noteWith('>\n  first\n second', '')
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
  })

  // A column-zero line that is neither a key nor a delimiter is content with no
  // key, which both readers refuse — and the continuation branch, which only
  // looks at indented lines, skipped it in silence.
  test('reports an unkeyed line at column zero', () => {
    const text = noteWith('summary', 'stray\nmetadata:\n  type: project')
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
  })

  // The tests from here to `reports a tab indenting a line before the first key`
  // pin a class of note this reader deliberately stopped reporting in #168.
  //
  // Each is a document `Bun.YAML` loads and pyyaml — a YAML 1.1 reader, and a
  // stricter one about where a tab may sit — refuses. The scanner reported them
  // because it was not a reader at all: a second, independent reader was the
  // only evidence it could offer that a value was ambiguous. A real parser
  // resolves each of these to exactly the text the index publishes, so there is
  // nothing left for this reader to disagree with.
  //
  // Reporting them again would need this file to decide, from the source,
  // whether a scalar was written *plain* — a tab inside a quoted scalar is
  // unambiguous, and the test below pins that it stays accepted. That decision
  // is the scanner, and thirty-one review rounds on #156 could not finish
  // enumerating it. The guard that replaces them is the one no enumeration is
  // needed for: a document the parser refuses is reported, whatever refused it.
  test('accepts a tab in a plain scalar on the key line', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: first\tsecond')
    // Folded to a space like every other break-or-tab, because an index entry
    // is one line — asserted, so a parser that dropped the tail would not pass.
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first second' }, problems: [] })
  })

  test('keeps a tab that is quoted', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: "first\tsecond"')
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // A comment line is dropped before it is ever measured: a tab inside one is
  // not indentation, and pyyaml loads this note as `first`.
  test('keeps a tab inside a comment following a plain scalar', () => {
    const text = noteWith(`first
  # note\twith tab`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // ...and a comment line that *starts* with a tab is one more of the same
  // class: pyyaml calls that tab indentation and refuses, `Bun.YAML` reads past
  // the comment and yields `first`, which is what the note says.
  test('accepts a comment line indented with a tab', () => {
    const text = noteWith(`first
\t# note`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // The same, with the tab behind a space rather than at the line's head.
  test('accepts a tab before a comment that follows a plain scalar', () => {
    for (const indent of [' \t', '  \t']) {
      const text = noteWith(`summary\n${indent}# note`, '')
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'summary' }, problems: [] })
    }
  })

  // The same again, where the comment also ends a block scalar. The scanner
  // needed a rule of its own for this seam — the block's exemption for a tab
  // ends with the block — and the parser needs none.
  test('accepts a tab before a comment that ends a block scalar', () => {
    const text = noteWith(`>\n  first\n \t# note`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // ...but at or past the block's own indentation a `#` is not a comment at
  // all — it is content, and so is the tab in front of it. pyyaml reads this
  // note as `first \t# note`.
  test('keeps a tab before a hash inside a block scalar', () => {
    const text = noteWith(`>\n  first\n  \t# note`)
    // Asserting the value, not only that nothing was reported: both readers
    // yield `first\n\t# note\n` here, and an index line is one line, so the
    // run of break-and-tab collapses to the single space this carries. A test
    // that checked `problems` alone would pass on a parser that dropped the
    // `# note` outright.
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first # note' }, problems: [] })
  })

  // ...and the last of the class: a tab-indented comment ahead of the first key.
  test('accepts a tab indenting a comment before the first key', () => {
    const text = '---\n\t# note\nname: a-note\ndescription: summary\n---\n'
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'summary' }, problems: [] })
  })

  // Only a space indents. A tab cannot supply the indentation a block scalar's
  // content owes its parent mapping, so `  description: >` over `  \ttext` is
  // a document pyyaml refuses — while one space further in, where the block's
  // own indentation is already met, the tab is content and it loads.
  test('reports a tab standing in for block indentation', () => {
    const under = '---\n  name: a-note\n  description: >\n  \ttext\n---\n'
    const met = '---\n  name: a-note\n  description: >\n   \ttext\n---\n'
    expect(parseFrontmatter(under).problems).not.toEqual([])
    expect(parseFrontmatter(met)).toMatchObject({ scalars: { description: 'text' }, problems: [] })
  })

  // YAML's character set excludes the C0 controls other than tab, newline and
  // carriage return, U+007F, and the C1 controls other than NEL. A strict
  // reader refuses one before any parse — so the note is unloadable to that
  // tool while the index published the character verbatim.
  //
  // This is the one rule `parseFrontmatter` still spells out itself after #168,
  // because `Bun.YAML` does not implement the production: it refuses U+0000 and
  // reads every other forbidden control point straight through into the value.
  // The loop below is the evidence — four of these five parse without a word.
  test('reports a raw control character anywhere in the frontmatter', () => {
    for (const forbidden of ['\u0000', '\u0008', '\u001F', '\u007F', '\u009F']) {
      const text = `---\nname: a-note\ndescription: before${forbidden}after\n---\n`
      expect(parseFrontmatter(text).problems[0]).toEqual(expect.stringContaining('YAML does not allow'))
    }
  })

  // The character and a refused parse are separate reports, and the character
  // does not stand in for the refusal. U+0000 is the one forbidden point
  // Bun.YAML does refuse, so it earns both; the other four leave the block
  // readable, so the character is the only thing wrong with it.
  test('reports a refused parse alongside the character, not instead of it', () => {
    const refused = `---\nname: a-note\ndescription: before\u0000after\n---\n`
    expect(parseFrontmatter(refused).problems).toEqual([
      expect.stringContaining('YAML does not allow'),
      expect.stringContaining('not valid YAML'),
    ])
    const readable = `---\nname: a-note\ndescription: before\u007Fafter\n---\n`
    expect(parseFrontmatter(readable).problems).toEqual([expect.stringContaining('YAML does not allow')])
  })

  // ...and a parse failure the character did not cause is still reported. The
  // suppression this replaces named the character alone, so an unterminated
  // quote three lines below a stray U+007F went unmentioned.
  test('reports a parse failure a forbidden character did not cause', () => {
    const text = `---\nname: a-note\u007F\ndescription: "unterminated\nmetadata:\n  type: project\n---\n`
    expect(parseFrontmatter(text).problems).toEqual([
      expect.stringContaining('YAML does not allow'),
      expect.stringContaining('not valid YAML'),
    ])
  })

  // ...and the ones YAML does allow stay allowed, escapes included: pyyaml
  // reads `"before\0after"` as a string holding a NUL.
  test('keeps the characters YAML allows', () => {
    for (const allowed of ['\u0009', '\u0085', '\u00A0', '\u2028']) {
      const text = `---\nname: a-note\ndescription: "before${allowed}after"\n---\n`
      expect(parseFrontmatter(text).problems).toEqual([])
    }
    expect(parseFrontmatter(noteWith(String.raw`"before\0after"`)).problems).toEqual([])
  })

  // U+2028 and U+2029 are not line breaks to either reader — pyyaml and
  // Bun.YAML both keep them as characters — but they *are* line terminators to
  // JavaScript, so `.` could not cross one and the key matched nothing at all.
  // The description did not drift; it vanished, and silently.
  //
  // The value that survives is the collapsed one, because an index line is one
  // line: both readers yield `a<separator>b`, and that is the run this folds to
  // a single space. What matters is that the text is there and matches them.
  test('keeps a quoted description that holds a line separator', () => {
    for (const separator of ['\u2028', '\u2029']) {
      for (const quote of ['"', '\'']) {
        const text = `---\nname: a-note\ndescription: ${quote}a${separator}b${quote}\n---\n`
        expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'a b' }, problems: [] })
      }
    }
  })

  // Unquoted is the same class as the tabs above (#168): pyyaml refuses the
  // document, `Bun.YAML` folds the separator like any other line break, and the
  // folded value is what the index publishes either way.
  test('accepts a line separator in a plain scalar, folding it like a break', () => {
    for (const separator of ['\u2028', '\u2029']) {
      const text = `---\nname: a-note\ndescription: a${separator}b\n---\n`
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'a b' }, problems: [] })
    }
  })

  // `%` opens a directive, and `]`, `}` close flow collections that were never
  // opened: the parser refuses all three, so the note is reported as the
  // unloadable document it is.
  test('reports a description opening with a flow or directive indicator', () => {
    for (const value of ['%summary', ']summary', '}summary']) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
    }
  })

  // A leading `,` is not one of them. It closes nothing, because a comma is an
  // indicator only inside a flow collection — `Bun.YAML` reads the value as the
  // text it is, and the index publishes that text. (pyyaml refuses it; that
  // disagreement is the class #168 stopped reporting, above.)
  test('reads a description opening with a comma as the text it is', () => {
    const text = note('a-note', 'placeholder').replace('description: placeholder', 'description: ,summary')
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: ',summary' }, problems: [] })
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
    const text = noteWith(`|
  \tfoo`)
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  // ...and in a plain continuation, where the readers disagree, the same #168
  // call applies: `Bun.YAML` folds the tab in and the index says so.
  test('accepts a tab inside a plain continuation', () => {
    const text = noteWith(`first
  second\tthird`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first second third' }, problems: [] })
  })

  // Without an explicit indicator the first content line sets the indentation,
  // and a later line under it ends the scalar where YAML expects a key.
  test('reports block content under the inferred indentation', () => {
    const text = noteWith(`>
  first
 second`)
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
  })

  test('accepts block content that holds the inferred indentation', () => {
    const text = noteWith(`>
  first
  second`)
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
    const text = noteWith(`"done" # note
  junk`)
    expect(parseFrontmatter(text).problems).not.toEqual([])
  })

  // A tab cannot provide YAML indentation at all, so a tab-continued scalar is
  // a document neither reader will load — and this one folded it silently.
  test('reports a tab used as indentation', () => {
    const text = noteWith(`first
\tsecond`)
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
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
    expect(parseFrontmatter(negative).problems).toEqual([expect.stringContaining('the number `-5` rather than text')])
  })

  test('still accepts every valid block header', () => {
    for (const header of ['|', '>', '|2', '>-', '|+', '> # note']) {
      const text = noteWith(`${header}
  content here`)
      expect(parseFrontmatter(text).problems).toEqual([])
    }
  })

  // A block header may carry an explicit indentation indicator, and then the
  // content must actually meet it: a reader refuses `|2` over a line with one
  // space. The continuation branch accepted any indentation at all.
  test('reports block content under an explicit indentation indicator', () => {
    const text = noteWith(`|2
 first`)
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
  })

  test('accepts block content that meets the indicator', () => {
    const text = noteWith(`|2
  first`)
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'first' }, problems: [] })
  })

  // The first occurrence never reached `scalars` when it had no value, so the
  // repeat check could not see it and a malformed note passed silently.
  test('reports a repeat whose first occurrence had no value', () => {
    const text = noteWith(`# write this later
description: real`)
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('more than once')])
  })

  // Both readers take the last of a repeated key, so the index would not drift
  // — but the author wrote two summaries and one vanished silently, and YAML
  // requires mapping keys to be unique (js-yaml refuses the document outright).
  test('reports an indexed key given more than once', () => {
    const text = noteWith(`first
description: second`)
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('more than once')])
  })

  // The duplicate is found by renaming one occurrence and asking the parser
  // whether the key is *still* at the root, so a same-named key one level down
  // is not a repeat: the probe lands inside the nested mapping, where the test
  // does not see it. Deciding this from the source is what round 30 of #156 got
  // wrong, in the other direction — an outer key the scanner could not spell
  // left the root undecided and published a nested summary as the note's own.
  test('does not call a nested key of the same name a repeat', () => {
    const text = `---\nname: a-note\ndescription: real\nmetadata:\n  name: nested\n  description: nested summary\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: 'real' }, problems: [] })
  })

  // ...and it is still a repeat when a nested occurrence comes first, which is
  // why every candidate line is probed rather than only the first.
  test('reports a repeat that a nested occurrence precedes', () => {
    const text = `---\nmetadata:\n  description: nested\nname: a-note\ndescription: first\ndescription: second\n---\n`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('more than once')])
  })

  // A flow mapping puts both occurrences on one line, and YAML discards the
  // first exactly as silently as it does in the block form. Occurrences are
  // nominated by offset rather than by line so that shape is nominated too.
  test('reports a repeat written inside a flow mapping', () => {
    const text = `---\n{name: a-note, name: other, description: real}\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { name: 'other', description: 'real' },
      problems: [expect.stringContaining('more than once')],
    })
  })

  // A quoted key is the same key: `"description":` and `description:` resolve to one
  // mapping entry, and a repeat across the two spellings is discarded as
  // silently as a bare one. So is an explicit key (`? name` over `: text`).
  test('reports a repeat spelled with a quoted or explicit key', () => {
    const quoted = `---\nname: a-note\ndescription: first\n"description": second\n---\n`
    expect(parseFrontmatter(quoted)).toMatchObject({
      scalars: { description: 'second' },
      problems: [expect.stringContaining('more than once')],
    })

    const single = `---\nname: a-note\n'description': first\ndescription: second\n---\n`
    expect(parseFrontmatter(single).problems).toEqual([expect.stringContaining('more than once')])

    const explicit = `---\nname: a-note\n? description\n: second\ndescription: first\n---\n`
    expect(parseFrontmatter(explicit).problems).toEqual([expect.stringContaining('more than once')])
  })

  // ...and a value that merely wraps onto a line reading like the key is not a
  // repeat. The nomination is deliberately wide, so the parser is what rules.
  test('does not call a wrapped value that reads like the key a repeat', () => {
    const text = `---\nname: a-note\ndescription: see the\n  description\n  field\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'see the description field' },
      problems: [],
    })
  })

  // A quoted key may spell itself with escapes, and `"description":` is the
  // same key as `description:` to any reader that decodes them. Deciding that
  // from the source means transcribing YAML's escape table, which is the
  // scanner this file replaced — so the parser is asked what the token spells.
  test('reports a repeat whose key is spelled with an escape', () => {
    const text = `---\nname: a-note\ndescription: first\n"descrip\\u0074ion": second\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'second' },
      problems: [expect.stringContaining('more than once')],
    })
  })

  // ...and a quoted token that is not the key must not be nominated as one,
  // which is what asking the parser rather than matching the name buys.
  test('does not call another quoted key an occurrence of an indexed one', () => {
    const text = `---\nname: a-note\ndescription: only one\n"metadata":\n  "type": project\n---\n`
    expect(parseFrontmatter(text)).toMatchObject({
      scalars: { description: 'only one' },
      problems: [],
    })
  })

  // The key name appearing inside a *value* is not an occurrence of the key.
  // The nomination is loose on purpose, so what settles it is the parser: the
  // rename lands in the value, the probe key is not at the root, nothing fires.
  test('does not call the key name inside a value a repeat', () => {
    const text = `---\nname: a-note\ndescription: a name: like this is text\n---\n`
    expect(parseFrontmatter(text).problems)
      .toEqual([expect.stringContaining('not valid YAML')])
    const quoted = `---\nname: a-note\ndescription: "a name: like this is text"\n---\n`
    expect(parseFrontmatter(quoted)).toMatchObject({
      scalars: { description: 'a name: like this is text' },
      problems: [],
    })
  })

  // Block scalar content is literal: a leading `&`, `!` or quote is text, not
  // scalar syntax, so it must not be run through the quoted-scalar reader.
  test('keeps block scalar content literal', () => {
    for (const [content, expected] of [['&notanchor', '&notanchor'], ['"not quoted"', '"not quoted"'], ['!tag', '!tag']]) {
      const text = noteWith(`|
  ${content}`)
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: expected }, problems: [] })
    }
  })

  // Only `name` and `description` reach the index, so a top-level field that is
  // legitimately a number is not a note defect — reporting it failed `--check`
  // over a value the index never renders.
  test('ignores top-level fields the index does not read', () => {
    const text = noteWith('a summary', 'version: 2\ntags: [a, b]')
    expect(parseFrontmatter(text).problems).toEqual([])
  })

  test('reports a flow collection used as a description', () => {
    const kinds = { '[summary]': 'a sequence', '{summary: text}': 'a mapping' }
    for (const [value, kind] of Object.entries(kinds)) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text).problems)
        .toEqual([expect.stringContaining(`is ${kind} rather than text`)])
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

  // A frontmatter block is a mapping of `name:` and `description:`. Anything
  // else is valid YAML and has no keys to take, so it is reported rather than
  // silently indexed as a note with neither. `Bun.YAML` also answers an array
  // for a *multi-document* block, which lands in the same report.
  test('reports frontmatter that is not a mapping', () => {
    for (const body of ['- one\n- two', 'just a sentence', '42']) {
      const text = `---\n${body}\n---\n`
      expect(parseFrontmatter(text)).toMatchObject({
        scalars: {},
        problems: [expect.stringContaining('not a mapping')],
      })
    }
  })

  // An empty block is not malformed, only empty: the note has no `name:` and no
  // `description:`, and `noteEntry` says exactly that. Calling it "not a
  // mapping" would report a defect the frontmatter does not have.
  test('treats an empty frontmatter block as a note with no keys', () => {
    const text = '---\n\n---\n'
    expect(parseFrontmatter(text)).toEqual({ scalars: {}, problems: [] })
    expect(noteEntry('n.md', text).problems).toEqual([
      expect.stringContaining('no `name:`'),
      expect.stringContaining('no `description:`'),
    ])
  })

  // `name:` is judged the same way `description:` is — it is the index entry's
  // link text, so a number there is a label the frontmatter does not yield.
  test('reports a name that YAML resolves to something that is not text', () => {
    const text = '---\nname: 42\ndescription: real\n---\n'
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('`name:` is the number `42`')])
    // ...and the entry falls back to the file stem rather than listing `42`.
    expect(noteEntry('a-note.md', text).name).toBe('a-note')
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

  // An escape YAML does not define is invalid YAML, and `\U` admits eight
  // digits, so it can also name something that is not a code point at all. The
  // scanner had to decode escapes itself, which is why it needed a rule for
  // each: an undefined letter, a value past 0x10FFFF, a surrogate. The parser
  // refuses all three, and the only thing that still has to be true here is
  // that a note it refuses comes back as a *report* — not as a throw that takes
  // every other note's index down with it.
  test('reports an escape YAML does not define, rather than throwing', () => {
    for (const value of [String.raw`"over \UFFFFFFFF the end"`, String.raw`"a\qb"`]) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(() => parseFrontmatter(text)).not.toThrow()
      const { scalars, problems } = parseFrontmatter(text)
      // No text is carried over from a document that does not parse: guessing
      // at half of it is what put a value in the index that no reader yields.
      expect(scalars.description).toBeUndefined()
      expect(problems).toEqual([expect.stringContaining('not valid YAML')])
    }
  })

  // A quote that never closes is not a plain scalar — the note's YAML does not
  // parse at all, so listing it as though it were fine hides that.
  test('reports a quoted scalar that never closes', () => {
    // The third and fourth end with a quote character that closes nothing: it
    // is escaped. `endsWith` cannot tell those from a terminator.
    for (const broken of ['"unfinished', '\'unfinished', String.raw`"unfinished \"`, '"', String.raw`"a\"`]) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${broken}`)
      expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
    }
  })

  // The scanner wrote a sentence per defect, and got the sentence wrong: one
  // callback carried two unrelated problem kinds and wrapped a whole report
  // inside another, so an unterminated single quote and a plain `&anchor` were
  // both announced as double-quoted. `Bun.YAML`'s refusal is terse and always
  // accurate instead — but terse is not actionable on a twenty-line block, and
  // its `SyntaxError` carries no position into the YAML.
  //
  // So the position is recovered from the parser, and that is what this pins:
  // every malformed spelling is reported against the frontmatter line it sits
  // on, and no report nests a second one inside it.
  test('names the frontmatter line a malformed scalar sits on', () => {
    const report = (value: string): string =>
      parseFrontmatter(`---
name: a-note
description: ${value}
metadata:
  type: project
---
`).problems[0] ?? ''

    for (const value of [String.raw`"holds \q here`.concat('"'), String.raw`"unclosed`, String.raw`'unclosed`, '*alias', '@tag']) {
      expect(report(value)).toContain(`(line 2: \`description: ${value}\`)`)
      expect(report(value)).toStartWith('the frontmatter is not valid YAML — ')
    }

    // The line is the *last* one that still reads, not the first that fails: a
    // quoted scalar that wraps cannot close on its own line, so reporting the
    // first prefix that throws would name a line with nothing wrong with it.
    expect(parseFrontmatter('---\nname: a-note\ndescription: "wraps\n  fine"\nstray: : x\n---\n').problems)
      .toEqual([expect.stringContaining('(line 4: `stray: : x`)')])
  })

  // Locating the line costs one parse per line over a block whose own length
  // grows with the line count, so the scan is bounded. Past the bound the
  // refusal is still reported — it is the location that is dropped, and a
  // block that large is malformed in a way its author can see unaided.
  test('reports an oversized malformed block without locating the line', () => {
    const filler = Array.from({ length: 300 }, (unused, at) => `key${at}: value`).join('\n')
    const text = `---\nname: a-note\ndescription: "unterminated\n${filler}\n---\n`
    expect(parseFrontmatter(text).problems).toEqual([expect.stringContaining('not valid YAML')])
    expect(parseFrontmatter(text).problems[0]).not.toContain('(line ')
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

  // `&`, `*` and `!` cannot begin a plain scalar: a value starting with one is
  // an anchor, an alias or a tag, and the text is what follows it. The scanner
  // reported all three, because resolving an alias needs an anchor table and an
  // anchor table is a YAML parser. Now there is one, so they resolve — and the
  // index carries the text the note's value actually is, which is what it was
  // reporting *for* (#168).
  test('resolves an anchor, alias or tag to the text it stands for', () => {
    const cases: Record<string, string> = {
      '&summary concrete summary': 'concrete summary',
      '!!str concrete summary': 'concrete summary',
      // A tag is also how a note writes a summary that would otherwise resolve
      // to a number, so this one must come back as text and not be reported.
      '!!str 42': '42',
    }
    for (const [value, resolved] of Object.entries(cases)) {
      const text = note('a-note', 'placeholder').replace('description: placeholder', `description: ${value}`)
      expect(parseFrontmatter(text)).toMatchObject({ scalars: { description: resolved }, problems: [] })
    }

    // An alias resolves against the anchor it names...
    const anchored = '---\nname: &summary a-note\ndescription: *summary\n---\n'
    expect(parseFrontmatter(anchored)).toMatchObject({ scalars: { description: 'a-note' }, problems: [] })

    // ...and one that names nothing is a document no reader can load, which is
    // reported rather than indexed as the four characters `*sum`.
    const dangling = note('a-note', 'placeholder').replace('description: placeholder', 'description: *summary')
    expect(parseFrontmatter(dangling).problems).toEqual([expect.stringContaining('Unresolved alias')])
  })

  // YAML drops an escaped line break *and* the indentation after it, where
  // every other continuation joins with a space.
  test('joins an escaped line break with nothing, not a space', () => {
    const { scalars, problems } = parseFrontmatter(noteWith(`"one\\
  two"`))
    expect(scalars.description).toBe('onetwo')
    expect(problems).toEqual([])
  })

  // A trailing `\\` is an escaped backslash, not an escaped break, so that line
  // folds with a space like any other.
  test('still folds with a space after an escaped backslash', () => {
    const { scalars } = parseFrontmatter(noteWith(`"one\\\\
  two"`))
    expect(scalars.description).toBe('one\\ two')
  })

  // A note no reader can load has to fail the gate, not list with text nothing
  // agreed on. Asserted through `noteEntry`, because that is the path `--check`
  // takes: a block the parser refuses yields no `name:` and no `description:`
  // either, and all three lines are true of the note at once.
  test('an undefined escape makes the note fail --check', () => {
    const text = note('a-note', 'placeholder').replace(
      'description: placeholder',
      String.raw`description: "a\qb"`,
    )
    expect(noteEntry('n.md', text).problems).toEqual([
      expect.stringContaining('not valid YAML'),
      expect.stringContaining('no `name:`'),
      expect.stringContaining('no `description:`'),
    ])
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

  // The preflight tested only for a symlink, so a directory at an index path
  // passed it and then threw `EISDIR` mid-run — after an earlier agent's index
  // had already been written, which is the outcome the preflight exists to
  // prevent. Ordered so the writable agent sorts first.
  test('refuses a non-regular index path before writing anything', () => {
    mkdirSync(join(root, 'a-agent'))
    writeFileSync(join(root, 'a-agent', 'n.md'), note('a-note', 'a note'))
    mkdirSync(join(root, 'z-agent'))
    writeFileSync(join(root, 'z-agent', 'n.md'), note('a-note', 'a note'))
    mkdirSync(join(root, 'z-agent', INDEX_NAME))

    const { written, refusals } = rebuild(root)

    expect(refusals).toEqual([expect.stringContaining('not a regular file')])
    expect(written).toEqual([])
    expect(existsSync(join(root, 'a-agent', INDEX_NAME))).toBe(false)
  })

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
