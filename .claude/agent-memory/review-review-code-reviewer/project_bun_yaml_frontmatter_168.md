---
name: bun-yaml-frontmatter-reader-168
description: 'scripts/agent-memory-index.ts reads note frontmatter with Bun.YAML after PR #203 (issue #168) — Bun.YAML does not implement YAML''s c-printable set (it refuses only U+0000) and its SyntaxError carries no position into the YAML, so those two gaps are filled in the script and must survive an edit; every question must be asked in the parser''s terms and a fragment that must be decided from the source is handed back to the parser (a quoted key token is a YAML document, so reading it says which key it is) — all four review findings on the PR were the one mistake of reasoning about source spelling where the parser reads resolved values; the silent discards are recovered by differential probes, whose mask must neutralise everything the unmasking makes parseable (a comment holding `: ` broke this once) and whose stand-ins are searched for rather than fixed (a fixed one needs a collision guard, and that guard is a fail-open) and whose candidate nomination must admit every spelling the parser collapses to one key (`"description":`, `? description`, flow style); the pyyaml-divergence checks were dropped deliberately, so a finding that this reader and a stricter one disagree about a tab, a line separator or a YAML 1.1 type is answered by that decision, not by a new rule'
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
routinely a line with nothing wrong with it. That is one parse per line over a block whose
own length grows with the line count, so the scan is bounded at 200 lines — past it the
refusal is still reported and only the location is dropped.

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

Both stand-ins are private-use code points **searched for** rather than fixed, and the duplicate
probe's key is suffixed until it is absent. A fixed sentinel needs a "does the note already
contain it?" guard, and that guard is a fail-open the note's own content can trip. The search
covers the source *and the resolved values*, which differ: `description: "quoted \uE000 # still
text"` holds no private-use character as text and holds one after the escape decodes, so
searching the source alone picks the character the note itself carries and the restore step
rewrites it — reporting a correctly quoted value as cut.

## The one mistake all four review findings were

Four separate findings landed on #203, from four reviewers, and every one is the same error:
**reasoning about the source spelling where the parser reasons about the resolved value.**

| Written against the source | What the parser actually reads |
| --- | --- |
| mask the `#`, leave the rest of the line | the unmasked comment text is now YAML, and a `: ` in it refuses |
| match the key by the name `description` | `"descrip\u0074ion":` is the same key once escapes decode |
| pick a stand-in absent from the source text | `"quoted \uE000 # x"` has no PUA character in the source and one in the value |
| report that no stand-in is left | nothing was going to be masked; there was no `#` |

The reader is a parser now, so **every question has to be asked in the parser's terms**. When
something must still be decided from the source, the way to do it is to hand that fragment back to
the parser rather than to interpret it: a quoted key token is itself a YAML document, so
`readYaml('"descrip\u0074ion"')` returns `description` and no escape table is written here. That
move is available more often than it looks, and it is what keeps this file from growing a scanner
back one rule at a time.

## And what a probe has to *nominate*, which is every spelling the parser collapses

The duplicate probe nominates candidate offsets with a regex and lets the parser rule on them.
That regex first matched only a bare `description:`, so a repeat spelled `"description":` was never
nominated and never reported — `Bun.YAML` resolves the quoted and bare spellings to one key and keeps
the last, exactly as silently. Same for `'description':`, for the explicit key (`? description`
over `: text`), and for flow style (`{name: a, name: b}`). Three bot reviewers found the quoted
case independently, which is a fair signal for how visible it is once looked for.

The rule that falls out, and the mirror of the masking one above: **a nomination pattern must be
as wide as the set of spellings the parser treats as identical.** Loose costs a probe; narrow
costs a report. Nominate widely on purpose and let the parser be the thing that decides — a value
wrapping onto a line that reads like a key gets nominated here, probed, and correctly cleared.

## Where the duplicate report stops, and why the line is there (#205)

Four review rounds each found a further key spelling the nomination missed: flow style, quoted,
escaped (`"descrip\u0074ion":`), continued across a line. Each fix was a real lexical rule and each
was right. The fifth — a key spelled by an **alias** (`? &k description` / `: first` over `? *k` /
`: second`) — was **not** taken, and that decision is the durable part.

Nothing closes this set while `Bun.YAML` exposes no structure: no CST, no token stream, no
positions. Locating where a key is written is lexical work that cannot be delegated, so the
pattern can always be one spelling short. Four rounds of widening it is the shape that took the
old scanner to thirty-one rounds on #156.

So the boundary is stated instead of chased: **the report covers a key whose spelling is lexically
present at the key position, not one whose identity is defined elsewhere in the document.** It is
in the `keyOccurrences` doc comment, in `AGENTS.md`, and in #205.

Two things make that affordable, and both should be checked before anyone moves the line:

- **The index is correct either way.** It publishes what the parser resolved, so it never
  disagrees with a YAML reader. A missed duplicate report costs the *author* a warning; it never
  costs the *reader* a wrong summary. That is a different severity from the comment probe, where
  the index itself would have advertised a truncated summary.
- **Reachability is not uniform.** An inline `#` in prose forced 36 notes to be quoted; an
  anchored explicit key aliased as a second key is not something anyone writes by accident.

A finding of the form "here is one more spelling of a duplicate key" is therefore answered
by #205, not by another pattern. What would actually close it is a reader that refuses
duplicate keys (js-yaml does; `Bun.YAML` does not), which is a dependency decision, not a rule.

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

- The index generated for every committed note was byte-identical to the scanner's, and
  `--check` reported no problems. Re-run it on any change here: a byte-identical corpus is
  the evidence that carries, and it survived the review fixes as well as the rewrite.
- Anchors, aliases and tags now resolve rather than being reported: `!!str 42` is the string `42`,
  and an alias naming no anchor is an "Unresolved alias" load failure.
- The script's interface is unchanged — same exports, same exit codes (`EXIT_PROBLEMS` 2,
  `EXIT_INVARIANT` 3), same `--check` behaviour — so the CI step, `mise run install` and
  `orca.yaml`'s worktree setup were untouched. See [[agent-memory-index-129]] for the
  `trackedIndexFiles` invariant, which this change did not go near.
- `AGENTS.md`'s Agent Memory section described the old reader and was corrected in the same PR.
