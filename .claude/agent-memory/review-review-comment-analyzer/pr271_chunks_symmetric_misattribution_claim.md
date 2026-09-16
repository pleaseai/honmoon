---
name: pr271-chunks-symmetric-misattribution-claim
description: PR #271 (issue #258) — the chunks() JSDoc in scripts/check-wiki-bundle-current.ts claimed a format it can't read "misattributes both sides symmetrically rather than inventing a difference between them"; reproduced that it invents a nonexistent page name instead, and the claim's own precondition (a stale bundle already exists) guarantees asymmetry, not symmetry
metadata:
  type: project
---

`chunks()` in `scripts/check-wiki-bundle-current.ts` is run independently over `expected`
(generator's fresh render) and `actual` (committed bundle). Its JSDoc claimed: "a format this
cannot read misattributes both sides symmetrically rather than inventing a difference between
them." Reproduced this is false by constructing a case where only `actual`'s copy of a page
contains a line that starts with `<doc path="fake">` at column 1 (BUNDLE_DOC's `^<doc\s...`
anchor) — e.g. because a real edit removed that line from the page and the bundle was never
regenerated. Result: `compareBundle` reports `inlines \`fake\`, which the generator does not` —
a page name that names no real file — and never mentions the page that actually changed. That is
inventing a difference, and it is asymmetric (only the side holding the bogus line is affected),
not symmetric misattribution.

Also confirmed the claim's precondition makes "symmetric" vacuous even where it would hold: if
both sides carry the *same* unreadable content unchanged, `compareBundle`'s `actual === expected`
short-circuit fires before `chunks()` ever runs, so the "symmetric" framing is never exercised in
the one case where it would be true. `chunks()` only runs once the two strings already differ,
which is exactly when the malformed content is most likely to differ between them too.

**How to apply:** when a JSDoc claims two independent applications of the same parsing function
"behave symmetrically" or "misattribute consistently" on two input strings that are known to
differ, don't accept "same code path on both" as proof — construct the case where the pathological
input differs between the two strings (not just the normal content) and run it. See also
[[postgres_sync_point_protocol_claims]] and [[pr197_program_for_dead_arm]] for the same pattern:
a comment's guarantee has to be executed against its own stated precondition, not read.
