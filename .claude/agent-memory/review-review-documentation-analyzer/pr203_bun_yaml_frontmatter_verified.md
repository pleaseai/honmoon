---
name: pr203-bun-yaml-frontmatter-verified
description: 'PR #203 (issue #168) swapped scripts/agent-memory-index.ts''s hand-written frontmatter scanner for Bun.YAML — every AGENTS.md claim was verified true by running the code rather than reading it, and the corpus was re-generated with both readers and diffed; the only defect the pass found was in the PR body''s own line-count arithmetic, which is the claim site review keeps missing because no gate reads it'
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

**The one defect:** the PR body's own line-count claim was wrong — it read `-806 / +594` where
`git diff origin/main...HEAD --shortstat` gave 599 insertions. Deletions matched; insertions were
off by five. Low-severity as arithmetic, but a genuine claim site with no gate reading it, and the
numbers moved again when the review fixes landed. Recount on the **final** head, never from a
number written mid-PR — see [[pr-body-is-a-fourth-claim-site]].

This is a clean-PR calibration point for how much the coverage-first mandate costs when every
claim actually holds: ~10 direct code probes were needed to confirm zero doc/code mismatches
beyond the one PR-body number. (The counts quoted above — notes, tests, suite totals — were
taken at that round and have since moved; the method is the durable part, not the figures.)
