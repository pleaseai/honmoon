---
name: pr271-chunks-symmetric-misattribution-claim
description: "A JSDoc claim that two independent parses of two differing strings behave symmetrically is checkable and was false in PR #271 — construct the case where the pathological input differs between the sides, not just the normal content"
metadata:
  type: project
---

`chunks()` in `scripts/check-wiki-bundle-current.ts` runs independently over `expected` (the
generator's fresh render) and `actual` (the committed bundle). Its JSDoc claimed: "a format this
cannot read misattributes both sides symmetrically rather than inventing a difference between
them." That was **false, and was corrected in #271 before merge.**

Reproduced by constructing a case where only `actual`'s copy of a page still holds a line starting
`<doc path="fake">` at column 1 — the `BUNDLE_DOC` anchor — because the real edit that produced
`expected` removed it. `compareBundle` then reports ``inlines `fake`, which the generator does
not``: a page name matching no file, produced on the malformed side alone, and the finding never
mentions the page that actually changed. That is inventing a difference, and it is asymmetric.

The claim's own precondition also makes "symmetric" vacuous where it would hold: if both sides
carry the same unreadable content unchanged, `compareBundle`'s `actual === expected`
short-circuit fires before `chunks()` runs at all. `chunks()` executes only once the two strings
differ — exactly when the malformed content is most likely to differ between them too.

**Current state (merged wording):** the JSDoc now says it does *not* misattribute symmetrically,
that such a line invents a section on one side alone, that the finding can name a page matching no
file, and that only the message is affected because the verdict is byte equality. Do not re-flag
it; the claim it makes now is the reproduced behaviour.

**How to apply:** when a JSDoc claims two independent applications of one parsing function
"behave symmetrically" or "misattribute consistently" over two strings that are known to differ,
do not accept "same code path on both" as proof. Construct the case where the *pathological*
input differs between the two strings, not just the normal content, and run it. See also
[[postgres_sync_point_protocol_claims]] and [[pr197_program_for_dead_arm]] for the same pattern:
a comment's guarantee has to be executed against its own stated precondition, not read.
