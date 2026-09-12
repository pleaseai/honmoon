---
name: pr203-bun-yaml-frontmatter-verified
description: 'PR #203 (issue #168) swapped scripts/agent-memory-index.ts''s hand-written frontmatter scanner for Bun.YAML — every AGENTS.md claim-by-claim assertion and the byte-identical-96-notes PR body claim were verified true by running the code directly; the only defect found was the PR body''s own line-count arithmetic (-806/+594 claimed vs actual 599 insertions)'
metadata:
  type: project
---

Reviewed by running `bun -e` probes directly against `parseFrontmatter`/`noteEntry` for every
scenario `AGENTS.md`'s rewritten "Agent Memory" section names (inline `#` cut, flow collection,
number incl. `1e3`/`0644`, `null`/`~`, unreadable block reported with line number, leading
`&`/`*`/`!` resolving, alias-naming-no-anchor as a load failure, bare date, `1_000`, `12:00`) —
all matched the prose exactly. Also reproduced the PR body's "byte-identical across 96 committed
notes" claim by running both the pre-#203 scanner and the new `Bun.YAML` reader against the same
`origin/main` corpus in separate scratch trees (`/tmp/oldrepo`, `/tmp/newrepo`) and diffing the
generated `MEMORY.md` files — `diff -rq` came back clean. `131 tests` (own file) and `270 pass, 0
fail` (full suite) both matched exactly.

**The one defect:** the PR body's own `-806 / +594` line-count claim is wrong — `git diff
origin/main...HEAD --shortstat -- scripts/agent-memory-index.ts scripts/agent-memory-index.test.ts`
gives `599 insertions(+), 806 deletions(-)`. Deletions match; insertions are off by 5. Low-severity
(pure arithmetic, doesn't misrepresent behavior) but a genuine PR-body claim site, consistent with
[[pr-body-is-a-fourth-claim-site]] — worth a fresh re-count on the final head rather than trusting
a number written mid-PR.

This is a clean-PR calibration point for how much the coverage-first mandate costs when every
claim actually holds: ~10 direct code probes were needed to confirm zero doc/code mismatches
beyond the one PR-body number.
