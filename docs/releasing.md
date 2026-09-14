# Releasing

Honmoon ships one artifact: the `honmoon` binary, built from the Rust workspace with the
dashboard embedded, published as a GitHub Release.

Releases are cut by [release-please](https://github.com/googleapis/release-please) from the
Conventional Commits on `main`. Two workflows split the work:
[`release-please.yml`](../.github/workflows/release-please.yml) owns the version, the
CHANGELOG, the tag, and the Release; [`release.yml`](../.github/workflows/release.yml) builds
the binaries and uploads them onto that Release. Nobody bumps a version or pushes a tag by
hand.

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

1. **Merge your work to `main` with Conventional Commits.** A breaking change (`feat!:` or a
   `BREAKING CHANGE:` footer) bumps the minor while the major is still `0`; `feat:` bumps the
   minor; *everything else* — `fix:`, `perf:`, and also `docs:`, `chore:`, `refactor:`,
   `test:`, `ci:` — bumps the patch. The hidden types are hidden from the CHANGELOG only, not
   from the version: release-please has no notion of a commit that does not count.

2. **Review the release PR.** Every push to `main` refreshes an open PR titled
   `chore(release): vX.Y.Z`, carrying the new version across every manifest and the CHANGELOG
   entry it will publish. It only ever *proposes* — nothing is tagged or published while it
   sits there, and the version it names keeps climbing to the largest bump among the commits
   since the last release. So a docs-only week is not a release until you decide it is. Edit
   the CHANGELOG in the PR if the generated entry needs trimming — what it says at merge time
   is what the Release notes say.

3. **Merge the release PR.** That is the whole release. release-please tags `vX.Y.Z`,
   publishes the Release with the CHANGELOG entry as its notes, and then calls `release.yml`,
   which builds the three targets and uploads the tarballs plus `SHA256SUMS` onto it.

4. **Watch the run.** `gh run watch` or the Actions tab. Until the build finishes the Release
   is live but carries no binaries — a window of roughly the build's length.

To cut a version release-please would not pick on its own, put `Release-As: 0.3.0` in a commit
body on `main`. A version carrying a pre-release identifier (`v0.2.0-rc.1` — anything with a
`-`) is marked a GitHub pre-release and never becomes "latest".

`scripts/bump-version.ts` predates release-please and is no longer part of this path; the
version sites are the `extra-files` list in
[`release-please-config.json`](../release-please-config.json).

## What the workflow does

| Job | What it does |
| --- | --- |
| `release-please` | Maintains the release PR. On the push that merges it, tags `vX.Y.Z` and publishes the Release, then calls `release.yml` with that tag. Runs as the org release GitHub App, not `GITHUB_TOKEN`, so its events reach other workflows — that is what gives the release PR CI. |
| `verify-version` | Reads `[workspace.package].version` via `cargo metadata` and compares it against the tag and against every `package.json` and the Claude plugin manifest. Fails naming the file that disagrees. This is the backstop for `extra-files`: a version site release-please failed to rewrite is caught here rather than shipped. |
| `build` (×3) | Builds `apps/dashboard` with Bun **first**, asserts the bundle is not `build.rs`'s placeholder, then `cargo build --release --locked -p honmoon-cli --target <target>` on a native runner. Smoke-tests `honmoon --version`, packages `honmoon` + `LICENSE` + `README.md` into `honmoon-<version>-<target>.tar.gz`, and uploads it with its `.sha256`. |
| `release` | Skipped on a dry run. Downloads every artifact, folds the per-target checksums into one `SHA256SUMS`, re-verifies it, and uploads onto the Release release-please already published. This is the only job with `contents: write`. |

The dashboard build order is not cosmetic. `crates/honmoon-mgmt/build.rs` writes a placeholder
`index.html` when `apps/dashboard/dist` is missing so a bare `cargo build` still links, which
means a cargo-first release would *succeed* and ship a binary whose dashboard reads "Dashboard
not built". The explicit grep in the build job is what turns that into a failure.

## Dry-running the pipeline

Run `release.yml` manually with an empty `tag` — from the Actions tab, or:

```bash
gh workflow run release.yml --ref main
```

That builds all three targets and uploads the tarballs as workflow artifacts, but touches no
Release and skips the tag comparison. Use it after changing the workflow, or to confirm the
binaries build before cutting anything.

Passing a `tag` instead re-runs the upload onto that existing Release, which is how you redo
an upload that failed after the Release was already published.

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
