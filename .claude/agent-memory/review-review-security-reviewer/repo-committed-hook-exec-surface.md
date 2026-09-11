---
name: repo-committed-hook-exec-surface
description: A repo-committed Claude Code hook that invokes a tracked script is an RCE surface — the hook config is reviewed once, the script it runs stays mutable; honmoon proposed one in PR #156 and dropped it for that reason, so the repo currently has none
metadata:
  type: project
---

PR #156 (issue #129) proposed a `SessionStart` hook in `.claude/settings.json` running
`bun "$CLAUDE_PROJECT_DIR/scripts/agent-memory-index.ts"`, to keep the generated agent-memory
index fresh in a new checkout. **It was removed before merge and is not in the repo** — do not
look for it, and do not flag its absence.

**Why it was removed, which is the durable part.** The hook *configuration* is what a reviewer
approves; the file it invokes is an ordinary tracked script any later PR can rewrite. So the
approved-once config plus a mutable target means checking out a contributor branch and opening a
session runs whatever that branch put in the script, with the developer's full privileges, before
anyone reads the diff. That is a real delta from "checking out a hostile branch executes nothing",
and it matters more here than in most repos, because reviewing contributor branches locally is
this repo's normal workflow.

It was also not load-bearing: `mise run install`, `bun run agent-memory:index` and the CI
`--check` step already cover regeneration, and the index is git-ignored, so a stale one costs a
missing pointer list rather than lost memory.

**How to apply:** treat any PR that adds a project-committed hook (`.claude/settings.json`
`hooks`, or an equivalent) as a supply-chain change, not a tooling change — ask what the hook
invokes, whether that target is mutable by a later PR, and whether a non-executing mechanism
(a documented task, a CI step) covers the same need. Related: [[policy-yaml-trust-boundary]],
which is the opposite case — author-controlled local input that is deliberately *not* a trust
boundary.
