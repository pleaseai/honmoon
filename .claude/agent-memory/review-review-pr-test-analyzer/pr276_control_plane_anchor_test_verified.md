---
name: pr276-control-plane-anchor-test-verified
description: "PR #276 (issue #266) added a describe block re-deriving control-plane.md's mgmt-API anchors from router()/lib.rs with no hardcoded line numbers — mutation-tested every assertion (marker reword, row rename, anchor-count-0, wrong Sources range) and all fail loudly; zero findings"
metadata:
  type: project
---

PR #276 repointed six stale `honmoon-mgmt/src/lib.rs` citations on
`wiki/deep-dive/control-plane.md` (issue #266) and added
`describe('control-plane.md shows the management API it cites')` to
`scripts/check-wiki-source-anchors.test.ts`.

Audited by mutating a working-tree copy of `control-plane.md` (never `git
stash`, always `git checkout -- <file>` immediately after each check, verified
clean with `git status --short`):

- Rewording the credential-paragraph marker string -> `after()`'s
  `expect(at).toBeGreaterThanOrEqual(0)` fails loudly (not silently skipped).
- Renaming a route-table row label -> the `page.split('\n').find(...)` lookup
  returns `undefined`, caught by `expect(row).toBeDefined()`.
- Stripping a row's markdown link (citation count 0) -> caught by
  `expect(anchors).toHaveLength(1)`.
- Repointing the `<!-- Sources: ... -->` diagram comment to an unrelated range
  -> caught by the `toContain('fn list_approvals(')` etc. loop.

All four mutations failed the suite; none passed vacuously. Confirmed against
`git show origin/main:wiki/deep-dive/control-plane.md` that the pre-fix page's
`lib.rs:86-93` anchor genuinely displayed `HookKey`/`HookSalt` doc comments,
not `list_audit` — the test would have been red before this PR.

Also confirmed: of the 7 `ROUTE_ROWS` entries, only 4 (audit, policy, healthz,
fallback) were actually repointed by this PR — approvals/approve/reject
anchors were already correct pre-PR (the two "filed as stale but are not"
citations the block's own comment calls out). No repointed citation from the
diff is left unexercised by the new block, and it hardcodes no line numbers
(binding strings + handler names only, both read back out of the tree).

No coverage gaps, weak assertions, or vacuous-pass risks found in this block.
See [[enumerate-from-the-wrong-side]] and
[[docs-completeness-claim-unbounded-review]] for adjacent wiki-anchor review
patterns in this repo.
