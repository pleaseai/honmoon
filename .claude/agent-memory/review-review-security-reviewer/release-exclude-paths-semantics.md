---
name: release-exclude-paths-semantics
description: "What honmoon's release-please `exclude-paths` list can and cannot do (PR #280, issue #279) — the drop rule is all-files-under-an-excluded-prefix, it can only suppress a bump and never cut one, and nothing in the release archive or the release build derives from the six excluded directories, each verified once"
metadata:
  type: project
---

`release-please-config.json` → `packages["."].exclude-paths` is
`[".claude", ".please", "datasets", "docs", "scripts", "wiki"]` (PR #280, issue #279).

**Why:** a `feat(scripts):` commit touching only `scripts/`, `wiki/` and `.claude/`
(`71ff6b5`) proposed v0.2.0 an hour after v0.1.0 — a minor bump of a binary it did not
change.

**How to apply:** these are the mechanics, verified against `release-please` 17.6.0
(`build/src/util/commit-exclude.js`, `commit-utils.js`, `github.js`), so do not re-derive
them when this list is touched again:

- The drop rule is `!files.every(f => under some excluded prefix)` → a commit is dropped
  only when *every* file it touches is excluded. One file outside is enough to keep it.
- Matching is a literal prefix `file.indexOf(path + '/') === 0` after
  `normalizePaths` strips surrounding slashes. So it is top-level-only (`docs/` matches,
  `crates/x/docs/` does not), and a glob entry such as `wiki/**` would match nothing.
- `!commit.files` → the commit is **kept**. The failure direction is "release anyway",
  never "silently suppress".
- File lists are not silently truncated: the manifest passes `backfillFiles: true`, so a
  PR with more than 100 files is re-fetched over REST (`getCommitFiles`, warns past 3000).
- `exclude-paths` can only *remove* commits from the bump and the CHANGELOG. It can never
  cause a release to be cut, so it is not a path to an unauthorised release.
- `policies/` is **not** on the list even though `agent.yaml` is `include_str!`'d only by a
  `#[cfg(test)]` test and a bench. That was decided at PR #280, not overlooked: it is product
  surface (the README quickstart runs every command against it; the guard test is named
  `shipped_example_policy_fires`), so a change to it should cut a release. `datasets/` was
  added to the list at the same review for the opposite reason — eval tooling only.
- `.github` is **not** on the list, and the residual that leaves is already documented and
  accepted in the release-please.yml header: ci.yml, codspeed.yml, the deploy-*.yml files and
  dependabot.yml decide nothing about the archive, so a `feat:`/`fix:` commit confined to one
  of them still bumps. release.yml cannot be split off — workflow files are all flat in
  `.github/workflows/` and `exclude-paths` matches whole directories. Answer this on the merits
  if it is raised again; do not re-file it and do not widen the list.

Verified once, at PR #280, that no excluded directory reaches anything the version names:
the archive is `honmoon`, `LICENSE`, `README.md` (`release.yml` `tar -czf`); the only
`include_str!` into a crate is `policies/agent.yaml` (not excluded); root
`workspaces` is `packages/*` + `apps/*`, so `wiki/` (its own `bun.lock`, private
vitepress site) is not installed by the release build's `bun install`. Re-check these four
if a directory is added to the list. The CI guard scripts under `scripts/` still run from
`ci.yml` on every PR — excluding the path changes release notes, not enforcement. See
[[dashboard-shell-csp]] and [[release-pipeline-draft-invariant]].
