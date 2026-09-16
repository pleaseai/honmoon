# Releasing

Honmoon ships one artifact: the `honmoon` binary, built from the Rust workspace with the
dashboard embedded, published as a GitHub Release.

Releases are cut by [release-please](https://github.com/googleapis/release-please) from the
Conventional Commits on `main`. Two workflows split the work:
[`release-please.yml`](../.github/workflows/release-please.yml) owns the version, the
CHANGELOG, the tag, and the Release; [`release.yml`](../.github/workflows/release.yml) builds
the binaries, uploads them onto that Release, and publishes it. Nobody bumps a version or
pushes a tag by hand.

The Release is created as a **draft** and published only once its binaries are on it, so a
release is never visible without them. Everything that follows from that is under
[When a release fails](#when-a-release-fails).

## What is and is not published (v0.1.0)

- **Binaries** — published to [GitHub Releases](https://github.com/pleaseai/honmoon/releases)
  for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and `aarch64-apple-darwin`.
- **npm packages** (`@honmoon/cli`, `@honmoon/policy`, `@honmoon/api`) — **not published**.
  Their public API is still moving with the gateway; publishing now would freeze it under
  semver before it has settled.
- **Rust crates** (`honmoon-core`, `honmoon-proxy`, `honmoon-mgmt`, `honmoon-cli`) — **not
  published to crates.io**. They are workspace-internal: only `honmoon-cli` is a product
  surface, and it ships as a binary.

## Cutting a release

1. **Merge your work to `main` with Conventional Commits.** Only four types open a release at
   all: `feat:` bumps the minor, and `fix:`, `perf:` and `revert:` bump the patch. A breaking
   change (`feat!:` or a `BREAKING CHANGE:` footer) bumps the minor too while the major is
   still `0`, whatever type carries it. `docs:`, `chore:`, `style:`, `refactor:`, `test:`,
   `build:` and `ci:` are release-please's *hidden* types: they render nothing in the
   CHANGELOG, and it drops a release whose entry would be empty, so a stretch of only those
   commits produces no release PR. They ride along in the next release a visible commit opens,
   adding no bump of their own.

   The type is not the only gate. A commit whose files *all* sit under `.claude`, `.please`,
   `datasets`, `docs`, `scripts` or `wiki` is dropped regardless of its type: none of those directories is
   an input to the binary, the packages or the README, so a `feat:` confined to them ships
   nothing and bumps nothing (#279). One file outside them is enough to make the whole commit
   count, so a change that also updates the wiki is unaffected. The list is `exclude-paths` in
   [`release-please-config.json`](../release-please-config.json); why those directories and not
   `.github` is in the header of
   [`release-please.yml`](../.github/workflows/release-please.yml).

2. **Review the release PR.** Every push to `main` refreshes an open PR titled
   `chore(release): vX.Y.Z`, carrying the new version across every manifest and the CHANGELOG
   entry it will publish. It only ever *proposes* — nothing is tagged or published while it
   sits there, and the version it names keeps climbing to the largest bump among the commits
   since the last release. Edit the CHANGELOG in the PR if the generated entry needs trimming
   — what it says at merge time is what the Release notes say.

3. **Merge the release PR.** That is the whole release. release-please tags `vX.Y.Z`, creates
   a draft Release with the CHANGELOG entry as its notes, and then calls `release.yml`, which
   builds the three targets, uploads the tarballs plus `SHA256SUMS` onto that draft, and
   publishes it as its last step.

4. **Watch the run.** `gh run watch` or the Actions tab. Nothing is visible to users until the
   run reaches that last step: while it is building, the tag exists and the Release does not
   appear on the releases page or at `/releases/latest`. If the run fails, see
   [When a release fails](#when-a-release-fails).

To cut a version release-please would not pick on its own — a specific number, or any release
at all out of hidden-type commits — put `Release-As: 0.3.0` in a commit body on `main`. The
footer is a note, and a commit carrying a note renders even under a hidden section, so it
clears the empty-CHANGELOG gate that would otherwise suppress the release. A version carrying a pre-release identifier (`v0.2.0-rc.1` — anything with a
`-`) is marked a GitHub pre-release and never becomes "latest".

`scripts/bump-version.ts` predates release-please and is no longer part of this path; the
version sites are the `extra-files` list in
[`release-please-config.json`](../release-please-config.json).

## What the workflow does

| Job | What it does |
| --- | --- |
| `release-please` | Maintains the release PR. On the push that merges it, pushes `refs/tags/vX.Y.Z`, creates the Release as a draft, then calls `release.yml` with that tag. |
| `verify-version` | Checks out the tag, then compares `[workspace.package].version` against the tag, every `package.json`, the Claude plugin manifest, and the README install snippets. Fails naming the file that disagrees. |
| `mark-prerelease` | Flags a tag carrying a pre-release identifier as a pre-release, while it is still a draft. Runs first and gates `build`. |
| `build` (×3) | Builds `apps/dashboard` with Bun **first**, then `cargo build --release --locked -p honmoon-cli --target <target>` on a native runner, from the tagged commit. Smoke-tests `honmoon --version` and packages each tarball with its `.sha256`. |
| `release` | Skipped on a dry run. Folds the per-target checksums into one `SHA256SUMS`, re-verifies it, uploads onto the draft, and then publishes it. Publishing is the last step of the last job, so nothing else can run against a Release users can already see. |

`release-please` runs as the org release GitHub App rather than as `GITHUB_TOKEN`, whose events
never reach other workflows — that is what gives the release PR its CI.

`verify-version` is the backstop for `extra-files`: a missed rewrite is only a warning on
release-please's side, so those version sites are re-checked before anything ships. The one
`extra-file` it does not cover is `Cargo.lock`, which `build`'s `cargo build --locked` fails on
instead. `build` depends on `mark-prerelease`, so a failed `gh release edit` cannot let the
run reach the step that publishes the draft — an unflagged pre-release would be published
straight to "latest". Its tag test is on the step, not the job, so a stable or dry run passes
through a job that succeeds while doing nothing — a job skipped by its own condition would
skip `build` with it. `mark-prerelease` itself depends on no job; while the Release was
published at tag time that kept a failing `verify-version` from stranding a pre-release at
`/releases/latest`, and the draft has since subsumed it, so what the missing edge buys now is
only that it runs alongside `verify-version` rather than after it. It and `release` are the
only jobs with `contents: write`.

The dashboard build order is not cosmetic. `crates/honmoon-mgmt/build.rs` writes a placeholder
`index.html` when `apps/dashboard/dist` is missing so a bare `cargo build` still links, which
means a cargo-first release would *succeed* and ship a binary whose dashboard reads "Dashboard
not built". The explicit grep in the build job is what turns that into a failure.

## When a release fails

Every failure before `release.yml`'s final step leaves the Release a **draft**. A draft is
listed for anyone with push access and invisible to everyone else: it is absent from the
public releases page, `/releases/latest` does not resolve to it, and its assets are not
publicly downloadable. So a half-finished release is not something users can find — it is
something you clean up.

Re-run `release.yml` with the tag once the cause is fixed (see
[Dry-running the pipeline](#dry-running-the-pipeline)). It rebuilds from the tagged commit,
re-uploads with `--clobber`, and publishes the draft. Nothing has to be reset first, and the
run is safe to repeat: the publish step edits the Release only while it is still a draft.

What this does cost is a window of a different shape, and it is worth knowing it is there.
The release PR merged before any of this ran, so `main` already carries the bumped manifests,
the README install snippets, and the CHANGELOG entry for a version that has no published
Release. The tree claims `0.2.0`; the releases page does not have it. That lasts until the
re-run succeeds, and it is the deliberate trade for never showing a stable Release with no
binaries on it — see issue #230. The README's install snippets are the visible edge of it:
they point at a download that does not exist yet.

One failure sits earlier than that and looks different. `force-tag-creation` makes
release-please push `refs/tags/vX.Y.Z` *before* it creates the Release, so if the Release
creation itself fails there is a tag and no Release at all, draft or otherwise — and
`release.yml` was never called. Re-run `release-please.yml` rather than `release.yml`: the tag
push is skipped when the ref already exists, and the Release is created from there.

The invariant behind all of this — the draft, the tag option that a draft makes mandatory, and
the publish being the last step — is asserted by `scripts/check-release-draft.ts`. Its test
runs under `bun test`, and the script reads the two files directly if you want to check them
before cutting anything:

```bash
bun scripts/check-release-draft.ts
```

Each of the three settings silently undoes the fix on its own, and none of them fails until a
release is actually being cut.

## Dry-running the pipeline

Run `release.yml` manually with an empty `tag` — from the Actions tab, or:

```bash
gh workflow run release.yml --ref main
```

That builds all three targets and uploads the tarballs as workflow artifacts, but touches no
Release and skips the tag comparison. Use it after changing the workflow, or to confirm the
binaries build before cutting anything.

Passing a `tag` instead builds **that tag's commit**, uploads onto that tag's existing
Release, and publishes it if it is still a draft — which is how you redo a release that failed
after the tag was cut. The checkout is pinned to the tag rather than to the ref the run was
launched from, so a manual run cannot put binaries built from some other branch onto a
Release. Run against a tag whose Release is already published, it re-uploads the assets and
leaves the Release's own settings alone, so re-dispatching an old tag cannot disturb which
release is "latest".

## Verifying a download

Every Release carries a `SHA256SUMS` covering all three tarballs.

```bash
VERSION=0.2.0
TARGET=x86_64-unknown-linux-gnu
BASE="https://github.com/pleaseai/honmoon/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/honmoon-${VERSION}-${TARGET}.tar.gz"
curl -fsSLO "${BASE}/SHA256SUMS"

# Linux
sha256sum --ignore-missing -c SHA256SUMS
# macOS
shasum -a 256 --ignore-missing -c SHA256SUMS
```

`--ignore-missing` restricts the check to the tarball actually downloaded; without it the two
files you did not fetch are reported as failures.
