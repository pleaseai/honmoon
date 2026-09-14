---
name: release-pipeline-draft-invariant
description: "How honmoon's release pipeline stays safe after #230 — the Release is a draft until release.yml's last step, which settings enforce it, what is already verified (no tag-push trigger anywhere, every third-party action SHA-pinned, TAG passed via env not $-brace interpolation), and the swallowed-gh-failure guard that #237 fixed"
metadata:
  type: project
---

Since #230 release-please creates the GitHub Release as a **draft** (`draft: true` +
`force-tag-creation: true` under `packages["."]` in `release-please-config.json`), and
`.github/workflows/release.yml`'s `release` job flips it live with
`gh release edit "$TAG" --draft=false` as its **last** step. `scripts/check-release-draft.ts`
asserts all three properties against the real files and runs in CI via `bun test`
(`.github/workflows/ci.yml`), so a regression on any one of them is caught.

**Why:** publishing at tag time left a stable Release with a CHANGELOG and no binaries at
`/releases/latest` for the length of three native builds, indefinitely if a runner failed.

**How to apply:** when reviewing this pipeline again, these are already verified and should not
be re-reported —

- No workflow in `.github/workflows/` triggers on a tag push (`ci`, `codspeed`, `deploy-*` are
  all `branches: [main]`), so `force-tag-creation` pushing `refs/tags/vX.Y.Z` as the org App
  opens no new trigger surface.
- Every third-party `uses:` in both release workflows is pinned to a 40-char SHA. The one
  unpinned reference is `uses: ./.github/workflows/release.yml`, the in-repo reusable call,
  which takes no SHA.
- `TAG` reaches every `run:` through `env:` and is used as `"$TAG"`; no `${{ }}` is interpolated
  into a `run:` body except `matrix.target`.
- In `release.yml`, `release` and `mark-prerelease` are the only jobs with `contents: write`
  (the file default is `contents: read`); `release-please.yml`'s `publish-binaries` declares it
  too, to pass down to the reusable call. That covers the GraphQL `repository.release(tagName:)`
  lookup `gh` uses to resolve a draft by tag, which needs only read.
- Failures before the last step fail *safe*: the Release stays a draft, invisible to users.

Settled, do not re-report: the publish step's draft read was once
`if [ "$(gh release view ... )" = "true" ]`, which swallowed a `gh` failure because `set -e`
does not fire for a command substitution inside an `if` condition — it printed "already
published" and exited 0. Fixed by the same PR that introduced the draft (#230 / PR #237),
which hoists the read to a plain assignment (`is_draft=$(gh release view ...)`) so the failure
aborts the job.
