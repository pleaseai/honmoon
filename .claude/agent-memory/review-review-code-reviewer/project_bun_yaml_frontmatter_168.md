---
name: bun-yaml-frontmatter-reader-168
description: 'scripts/agent-memory-index.ts reads note frontmatter with Bun.YAML after PR #203 (issue #168) — Bun.YAML does not implement YAML''s c-printable set (it refuses only U+0000) and its SyntaxError carries no position into the YAML, so those two gaps are filled in the script and must survive an edit; the silent discards are recovered by differential probes, whose mask must neutralise everything the unmasking makes parseable (a comment holding `: ` broke this once) and whose stand-ins are searched for rather than fixed, since a fixed one needs a collision guard that is a fail-open; the pyyaml-divergence checks were dropped deliberately, so a finding that this reader and a stricter one disagree about a tab, a line separator or a YAML 1.1 type is answered by that decision, not by a new rule'
metadata:
  type: project
---

`scripts/agent-memory-index.ts` (PR #203, issue #168) replaced a 400-line hand-written
frontmatter scanner with `Bun.YAML`. The scanner had drawn thirty-one review rounds on #156,
every finding the same shape — the scanner and a real YAML reader resolving one value
differently — and three of the fixes moved a boundary the other rules had been written against.

## Two gaps in `Bun.YAML` that the script fills, and that an edit must not remove

**It does not implement YAML's `c-printable` character set.** Measured on Bun 1.4.2: of U+0000,
U+0001, U+0008, U+001F, U+007F, U+0080 and U+009F it refuses only **U+0000** and reads the rest
straight through into the value, where a raw control character would be written verbatim into a
generated markdown index. `forbiddenCharacter` is therefore still spelled out in the script — the
one piece of YAML it writes itself. It is a closed set of code points, not a judgement about what
a scalar's *source* looked like, which is why it did not go with the rest of the scanner.

**Its `SyntaxError` carries no position into the YAML.** The `line`/`column` on the error point at
the `parse` call site in the calling `.ts` file, not into the document, and the message is terse
("Unexpected token"). `failingLine` recovers the location by asking the parser about prefixes: the
*longest* prefix of lines that still reads is the last line that can be right. Longest, not first —
a quoted scalar that wraps cannot close on its own line, so the first prefix that throws is
routinely a line with nothing wrong with it.

## What the script reports, and how

A parser resolves; it does not report, and reporting is what the derived index exists for. Four
things are reported:

- a character outside YAML's `c-printable` set (above), which is its own report and does **not**
  stand in for a refusal — a note can hold a stray U+007F *and* an unterminated quote, and an
  earlier revision named only the character;
- a block the parser refuses (with the line, above);
- a value resolving to something that is not text (`42`, `[a]`, a mapping) — `null` and `~` are
  the *absence* of a value, so they surface as `noteEntry`'s "no `description:`" instead;
- the two things YAML discards in **silence** — the text after an inline `#`, and every occurrence
  but the last of a repeated key.

Those last two are recovered by **differential parses**, not by source rules: mask one `#` and
read the block again (what comes back with the rest of the line attached was cut by a comment),
and rename one occurrence of a key and read again (if the key is *still* at the root, it was
written twice). This is the point of the change — neither probe needs to know whether a scalar
was written plain, or where the mapping's root indentation is, which is what round 30 of #156
got wrong.

## What a probe has to mask, which is more than the character it asks about

The comment probe masks the `#` **and every remaining `:` on that line**, restoring both before
it compares. Masking the `#` alone looks sufficient and is not: comment text is written under no
grammar, so unmasking a comment that holds `: ` (`description: fixed in PR #155: see docs`) turns
the line into an attempted nested mapping, the probe stops parsing, and the skip-on-refusal path
answers "nothing here" for the very value it was asked about. That was a **false negative in the
exact defect class this change exists to remove**, found in review of #203 and fixed there.

The general shape: a differential probe's skip-on-refusal path is only safe while the doctoring
cannot itself cause the refusal. Check what the mask *creates*, not only what it removes.

Both stand-ins are private-use code points **searched for in the note** rather than fixed, and
the duplicate probe's key is suffixed until it is absent. A fixed sentinel needs a "does the note
already contain it?" guard, and that guard is a fail-open the note's own content can trip.

## Deliberately dropped — do not re-file as a regression

The checks that reported a **disagreement between two readers**: a tab or a U+2028/U+2029 in a
plain scalar, and the YAML 1.1 type spellings 1.2 leaves as text (`1_000`, `12:00`, a bare date,
`yes`/`no`/`y`/`N`). `Bun.YAML` loads all of these and pyyaml refuses or retypes them.

They were dropped for two reasons, both recorded in the tests beside the cases they cover:
expressing them needs the script to decide *from the source* whether a scalar was written plain
(a quoted `"12:00"` is unambiguous), and that decision is the scanner; and they guard against a
reader this repository does not run — there is no pyyaml and no Python in it or its CI.

A finding of the form "this reader and a stricter one disagree about `<some YAML shape>`" is
therefore answered by that decision rather than by adding a rule. A finding that the *parser* and
the *index* disagree is a real defect and always was.

## What was checked at the time

- The index generated for all 96 committed notes was byte-identical to the scanner's, and
  `--check` reported no problems.
- Anchors, aliases and tags now resolve rather than being reported: `!!str 42` is the string `42`,
  and an alias naming no anchor is an "Unresolved alias" load failure.
- The script's interface is unchanged — same exports, same exit codes (`EXIT_PROBLEMS` 2,
  `EXIT_INVARIANT` 3), same `--check` behaviour — so the CI step, `mise run install` and
  `orca.yaml`'s worktree setup were untouched. See [[agent-memory-index-129]] for the
  `trackedIndexFiles` invariant, which this change did not go near.
- `AGENTS.md`'s Agent Memory section described the old reader and was corrected in the same PR.
