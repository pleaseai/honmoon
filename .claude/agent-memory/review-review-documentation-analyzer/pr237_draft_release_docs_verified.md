---
name: pr237-draft-release-docs-verified
description: "PR #237 (issue #230) draft-Release docs review, zero findings — the new When-a-release-fails section, the rewritten mark-prerelease paragraph, the workflow table and the guard script all verified against release.yml, release-please.yml and release-please-config.json; a clean-PR calibration point"
metadata:
  type: project
---

PR #237 rewrote docs/releasing.md, the header comments of release.yml and
release-please.yml, and added scripts/check-release-draft.ts (+ test) to assert the
draft-Release invariant for issue #230 (create the Release as a draft, publish only
after release.yml's binaries land).

Every claim named in the review brief checked out:

- Draft visibility claims (absent from public releases page, `/releases/latest`
  doesn't resolve, assets not publicly downloadable) match ordinary GitHub draft
  semantics — drafts are visible only to users with push access, independent of repo
  visibility.
- "the run is safe to repeat: the publish step edits the Release only while it is
  still a draft" matches release.yml's `release` job: `gh release view --json
  isDraft` gates a conditional `gh release edit --draft=false`.
- The `force-tag-creation` / tag-then-Release ordering and the "re-run
  release-please.yml, the tag push is skipped when the ref exists" recovery claim
  match the verified release-please v17.6.0 behavior (createRef with 422-caught
  first, then createRelease; `autorelease: pending` label only swaps to `tagged`
  after the releases are created, so a failed createRelease leaves the label
  pending and a re-run retries cleanly).
- `bun scripts/check-release-draft.ts` runs standalone (exit 0 against this repo's
  config/workflow); `bun test` (the repo's `test` script) picks up
  `check-release-draft.test.ts` automatically — both documented commands work.
- The rewritten `mark-prerelease` paragraph's reasoning — that draft-mode subsumes
  the old "runs first, no needs" protection against a failing `verify-version`,
  since nothing publishes until the final step regardless of ordering now — is
  logically consistent with the actual job graph (`build` needs
  `[verify-version, mark-prerelease]`, `release` needs `[verify-version, build]`,
  `mark-prerelease` needs nothing). This rewrite exists in both docs/releasing.md
  and release.yml's own comment, worded consistently.
- Section anchors `#when-a-release-fails` and `#dry-running-the-pipeline` resolve to
  real headings. No stale "published at tag time" / "binary-less window" prose
  remained anywhere in the repo (README.md, docs/releasing.md checked; no other .md
  files reference release.yml or release-please).
- release.yml's "Publish the Release" step changed midway through the review (a
  `set -e` fix hoisting the `gh release view` read to its own assignment line), and
  `check-release-draft.ts` changed again after that. Both were re-read; neither
  touches any claim above, which are all pinned to a job, a step or a file rather
  than to a revision.

No findings reported, and the reason is worth keeping: documentation claims here
were each pinned to one job, step or file, so verification converged. The failure
mode this calibrates against is the opposite shape — a claim quantified over every
case ("a complete account of X", "on any host") has no bounded check, so it earns a
fresh valid finding every review round. Narrow the claim rather than qualify it.
