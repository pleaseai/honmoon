---
name: ocr-scoping-honmoon
description: ocr Delegation Mode scoping, flags and rule resolution on honmoon — no default flags configured, rules match by extension, lockfiles and docs excluded, and --from/--to is needed on stacked PRs even with a clean tree
metadata:
  type: project
---

honmoon's `.please/config.yml` has no `review.ocr` / delegate flags section, so
`REVIEW_OCR_DEFAULT_FLAGS` re-derives to empty via `setup-env.sh --print`. Pass no extra
shared flags to `ocr delegate preview` / `rule` beyond the caller's scope flags. `ocr`
(from mise-installed node) is on PATH directly at
`~/.local/share/mise/installs/node/24/bin/ocr`, so no `bunx` fallback is needed here.

Rule resolution matches by **extension, not directory**: `**/Cargo.toml` (Cargo manifest
hygiene, edition/MSRV, feature flags, release metadata) and `**/*.rs` (a broad Rust set
covering ownership/lifetimes, panics/unwraps, unsafe boundaries, concurrency, async
cancellation, collections/perf, API design, macros, and security-sensitive input handling).

Expect these under the excluded-paths list rather than the reviewable ledger, all as
`unsupported_ext`: `Cargo.lock`, `mise.lock`, and the project docs (ADRs, README,
`docs/roadmap.md`, `wiki/*`). That is normal, not a warning. `.claude/agent-memory/**/*.md`
notes are excluded the same way — a workspace-mode change touching only these notes previews
as 0/N reviewable. When the dispatching task explicitly asks for a content review of such
notes (e.g. verifying review-agent memory claims against `origin/main` after a correction
commit), still load and review them by hand via `git diff`/`git show` and report findings in
the normal schema — don't let the 0-reviewable ocr result stand in for the actual review the
caller asked for; just note in the summary that ocr itself excluded every file as
`unsupported_ext`.

For a stacked-PR review where the caller passes `REVIEW_BASE_REF` (e.g.
`origin/amondnet/issue-85-endpoints-k8s-facts` for issue-86 built on issue-85), use
`ocr delegate preview --from "$REVIEW_BASE_REF" --to HEAD` **even when the working tree is
clean** — workspace-mode preview comes back empty in that case, and the caller usually wants
the committed range instead.

**Why:** saves a re-derivation step and sets expectations for what preview/rule output looks
like on future honmoon PRs reviewed with ocr.
**How to apply:** don't worry about the missing default flags (expected), don't treat
excluded lockfiles and docs as a problem, and reach for the range form on a stacked PR.

See [[honmoon-postgres-sql-classification]] for what got reviewed under this scope.
