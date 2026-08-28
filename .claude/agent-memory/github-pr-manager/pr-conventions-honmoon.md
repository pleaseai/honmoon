---
name: pr-conventions-honmoon
description: pleaseai/honmoon PR mechanics — no PR template, graphite tracks the repo but not feature branches, draft-by-default org
metadata:
  type: project
---

`pleaseai/honmoon` PR creation specifics:

- **No repository PR template.** `find-templates.sh pr` returns `status: not-found`
  (`.github/` holds only `workflows/`). Fall back to the generic skill template.
- **`detect-stack-tool.sh` reports `STACK_TOOL=graphite`, but most feature branches are not
  graphite-tracked.** Check `gt ls` before reaching for `gt submit` — an untracked branch
  should go through plain `gh pr create`. As of 2026-08 only `main` and
  `ci-update-github-actions` were tracked.
- **Linked issues carry no Asana URLs** — the extraction script exits 0 with empty output, so
  the `## Asana Tasks` section is correctly omitted.
- Draft-by-default applies (pleaseai org, automatic AI review on PR open).

**Why:** guessing the stack tool from repo-level detection alone produces a `gt submit`
failure on branches Graphite has never seen.

**How to apply:** on any honmoon PR, run `gt ls` after `detect-stack-tool.sh` and route on the
branch's actual tracking state, not the repo's.
