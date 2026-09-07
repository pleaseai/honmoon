# Releasing

Honmoon ships one artifact: the `honmoon` binary, built from the Rust workspace with the
dashboard embedded, published as a GitHub Release. Everything below is driven by
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

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

1. **Bump every manifest.** One version spans `Cargo.toml`'s `[workspace.package]`, the root
   `package.json`, and every `packages/*` / `apps/*` `package.json`. The script does all of
   them and refreshes `Cargo.lock`:

   ```bash
   bun run version:bump 0.2.0
   ```

   If it reports that it could not refresh `Cargo.lock` offline, run `cargo update --workspace`
   yourself and include the result.

2. **Commit and open a PR.**

   ```bash
   git checkout -b chore/release-0.2.0
   git commit -am 'chore(release): v0.2.0'
   gh pr create --fill
   ```

   CI must be green before the merge — the release workflow does not re-run the test suite.

3. **Merge, then tag `main`.** An annotated tag, because `gh release create --verify-tag`
   checks the tag exists on the remote:

   ```bash
   git checkout main && git pull
   git tag -a v0.2.0 -m 'honmoon v0.2.0'
   git push origin v0.2.0
   ```

4. **Watch the run.** `gh run watch` or the Actions tab. When it finishes, the Release is
   live with three `.tar.gz` files, a `SHA256SUMS`, and generated release notes.

A tag carrying a pre-release identifier (`v0.2.0-rc.1` — anything with a `-`) is published as
a GitHub pre-release and never becomes "latest".

## What the workflow does

| Job | What it does |
| --- | --- |
| `verify-version` | Reads `[workspace.package].version` via `cargo metadata` and compares it against the tag and against every `package.json`. Fails naming the file that disagrees. |
| `build` (×3) | Builds `apps/dashboard` with Bun **first**, asserts the bundle is not `build.rs`'s placeholder, then `cargo build --release --locked -p honmoon-cli --target <target>` on a native runner. Smoke-tests `honmoon --version`, packages `honmoon` + `LICENSE` + `README.md` into `honmoon-<version>-<target>.tar.gz`, and uploads it with its `.sha256`. |
| `release` | Tag pushes only. Downloads every artifact, folds the per-target checksums into one `SHA256SUMS`, re-verifies it, and runs `gh release create`. This is the only job with `contents: write`. |

The dashboard build order is not cosmetic. `crates/honmoon-mgmt/build.rs` writes a placeholder
`index.html` when `apps/dashboard/dist` is missing so a bare `cargo build` still links, which
means a cargo-first release would *succeed* and ship a binary whose dashboard reads "Dashboard
not built". The explicit grep in the build job is what turns that into a failure.

## Dry-running the pipeline

Run the workflow manually — from the Actions tab, or:

```bash
gh workflow run release.yml --ref main
```

A manual run builds all three targets and uploads the tarballs as workflow artifacts, but
creates no Release and does not compare against a tag (there is none). Use it after changing
the workflow, or to confirm the binaries build before committing to a tag.

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
