---
name: honmoon-pr-conventions
description: pleaseai/honmoon PR mechanics — no repo PR template, Graphite installed but most feature branches untracked, base is main
metadata:
  type: project
---

`pleaseai/honmoon` PR creation notes (verified 2026-08-26, PR #64):

- **No repository PR template.** `find-templates.sh pr` returns `status: not-found` — fall back to the skill's generic template (Summary / Changes / Test Plan / Related Issues).
- **Graphite is initialized in the repo** (`detect-stack-tool.sh` prints `STACK_TOOL=graphite`), but most feature branches are *not* tracked by `gt`. Always check `gt state` / `gt ls` before assuming a stack — for an untracked branch use `gh pr create`, not `gt submit`.
- Base branch is `main`. pleaseai org → draft by default.

**Why:** the graphite signal at repo level is misleading here and would otherwise push the wrong submit command.
**How to apply:** on any honmoon PR, run `gt ls` after `detect-stack-tool.sh` and route on the branch's actual tracking state.
