---
name: pr203-yaml-rewrite-no-test-weakened
description: "PR #203 (issue #168) swapped agent-memory-index.ts's hand-written YAML scanner for Bun.YAML — audited every test one by one, none was weakened or silently dropped; the audit method (trace every renamed test to a measured behaviour change, and require it to assert the resolved value rather than an empty problems array) is the reusable part, as is the reachability rule that turned one finding from add-a-test into delete-the-branch"
metadata:
  type: project
---

PR #203 rewrote `scripts/agent-memory-index.ts` (issue #168) to use `Bun.YAML.parse` instead of
a hand-written frontmatter scanner, and the 1274-line test file was rewritten with it. Counts
moved through the PR and are not the point; what the audit established is that the rewrite
*added* cases and re-pointed the rest at measured behaviour, and lost none.

Verified by diffing test names old vs new (`git show origin/main:...` vs HEAD): 12 old test names
disappeared and new ones appeared in their place. Traced every one of the 12 individually — each maps to a
genuine behavioral difference between the old scanner and Bun.YAML (e.g. tabs before comments
that pyyaml refused but Bun.YAML reads past, `,summary`/line-separator handling, anchors/aliases/
tags now *resolving* instead of being reported, the two-message "out-of-range codepoint"/
"undefined escape" tests collapsing into one generic "not valid YAML" refusal now that the parser
refuses the whole document rather than the scanner guessing at half of it). None of the renamed
"reports X" → "accepts X" flips is vacuous: every one asserts the *resolved value* via
`toMatchObject({ scalars: { description: ... } })`, not just `problems: []`, so a parser that
silently dropped text would still fail the test.

## The one gap found, and why "add a test" was the wrong fix

The first pass reported an uncovered branch: `isMapping()` excluded `instanceof Date` and
`describeValue()` had a dedicated `'a timestamp'` branch, both carrying doc comments saying a
`!!timestamp` tag resolves to a `Date`, and no test exercised either.

**Measured before acting, and the premise was false.** On Bun 1.4.2 `Bun.YAML` never produces a
`Date`: `!!timestamp 2024-01-01` resolves to the string `2024-01-01`, as does a bare
`2024-01-01`, `!!timestamp 2024-01-01T10:00:00Z` and every other spelling tried. So the branches
were unreachable and the comment justifying them was wrong — the fix is to delete them, not to
write a test that would have pinned a fiction into the suite.

That is the lesson worth keeping: **an "untested branch" finding is only half a finding until the
branch is shown to be reachable.** Adding the test is the reflex, and here it would have
manufactured permanent coverage for behaviour the parser cannot produce, and frozen a false claim
about `Bun.YAML` into a test name. Check reachability first; a branch that cannot be reached is a
deletion, and its confident doc comment is the thing that hid it.

See [[bun-yaml-frontmatter-reader-168]] for what `Bun.YAML` does and does not implement, and
[[project-uncompilable-condition-load-failure-191]] for the general pattern of checking whether a
PR's test rewrite is a real behaviour change or a coverage loss in disguise.
