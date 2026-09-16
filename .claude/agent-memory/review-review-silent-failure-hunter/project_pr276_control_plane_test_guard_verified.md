---
name: pr276-control-plane-test-guard-verified
description: "PR #276 added a describe block to check-wiki-source-anchors.test.ts tying control-plane.md's mgmt citations to router() handlers — mutation-tested clean, no silent-pass path found"
metadata:
  type: project
---

PR #276 (issue #266) repointed six stale citations on `wiki/deep-dive/control-plane.md` and
added a `describe('control-plane.md shows the management API it cites', ...)` block at the end
of `scripts/check-wiki-source-anchors.test.ts`. Mutation-tested every scenario the task brief
raised, each on a throwaway edit reverted immediately after:

- Marker reworded (`after()`'s `page.indexOf` returns -1) → `expect(at).toBeGreaterThanOrEqual(0)`
  throws before the `page.slice(at)` it guards ever runs. Clean, informative failure.
- Both citations removed from the credential paragraph → `after()` falls through to the *next*
  anchors in the document (the `route_layer` binding, then `mgmt_token.rs`) and the content check
  (`toContain('fn authorized(')`) fails loudly with the real router source dumped in the diff —
  not a silent pass, because the check is content-based (substring match), not just
  position-based.
- `shown()` on an anchor with a mismatched path → `expect(anchor.path).toBe(MGMT_LIB)` executes
  and throws *before* the slice line, so a wrong-file citation is reported as itself, never masked
  by slice output.
- Table row label reflowed/changed → `page.split('\n').find(...)` returns undefined,
  `expect(row).toBeDefined()` throws cleanly.
- `<!-- Sources: -->` comment's `lib.rs` segment removed → regex `.exec()` returns null,
  `expect(range).not.toBeNull()` throws before `range![1]` is read; no TypeError.
- `MGMT_LIB` pointed at a nonexistent file → the describe body's `readFileSync` throws
  synchronously during test collection; bun reports it as an "Unhandled error between tests" and
  the overall run exits 1 (verified via `$?`), so a broken fixture cannot pass with a green exit
  code even though it doesn't produce a per-test failure line.

Conclusion: every risky operation in this block is guarded by a `expect()` call that executes
strictly before the operation it protects (same-function, sequential statements — not deferred to
a later assertion), and every content check compares actual source substrings rather than trusting
position alone. No in-scope silent-failure finding was reportable against this PR's test additions.
Re-verify with the same mutation techniques (temp edit + `bun test` + revert + `git status --short`)
if this block is touched again — don't assume it's still airtight from this note alone.

See also [[honmoon-agent-memory-notes-go-stale]] — this note itself goes stale the moment someone
edits this describe block.
