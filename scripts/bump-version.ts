/**
 * Bump the workspace version across every manifest in the repo.
 *
 * `.github/workflows/release.yml` refuses to publish unless `Cargo.toml`'s
 * `[workspace.package].version`, the root `package.json`, and every
 * `packages/*` / `apps/*` `package.json` carry the same version — so they are
 * bumped together, by one command, rather than by hand.
 *
 * Usage: `bun scripts/bump-version.ts 0.2.0` (or `bun run version:bump 0.2.0`).
 *
 * Rewrites are surgical: exactly the one `version = "…"` line under
 * `[workspace.package]` and exactly the top-level `"version"` line of each
 * `package.json`. Nothing is re-serialized, so formatting is preserved byte for
 * byte. See docs/releasing.md for the full release procedure.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'

/**
 * semver core plus optional pre-release / build metadata (semver.org BNF).
 *
 * A *numeric* pre-release identifier may not carry a leading zero (`1.0.0-01`
 * is not a semver version, and `cargo` rejects it outright), while build
 * metadata may — so the two halves are spelled differently, as the BNF has it.
 * Getting this wrong would rewrite every manifest and only then fail in cargo.
 */
const PRE_RELEASE_ID = String.raw`(?:0|[1-9]\d*|\d*[a-z-][0-9a-z-]*)`
const SEMVER = new RegExp(
  String.raw`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)`
  + String.raw`(?:-${PRE_RELEASE_ID}(?:\.${PRE_RELEASE_ID})*)?`
  + String.raw`(?:\+[0-9a-z-]+(?:\.[0-9a-z-]+)*)?$`,
  'i',
)

/** Workspace roots scanned for member `package.json` files, in bump order. */
const WORKSPACE_DIRS = ['packages', 'apps']

export function isValidSemver(version: string): boolean {
  return SEMVER.test(version)
}

/**
 * Rewrite the `version = "…"` line of the `[workspace.package]` table only.
 *
 * Cargo manifests carry a `version` key in several tables (`[package]`,
 * `[workspace.dependencies]` entries, …), so the rewrite is scoped by tracking
 * the enclosing table header rather than replacing the first match.
 *
 * Throws when the table has no version line: silently returning the manifest
 * unchanged would let the other manifests bump past `Cargo.toml`.
 */
export function bumpCargoToml(text: string, version: string): string {
  let table = ''
  let done = false
  const bumped = text
    .split('\n')
    .map((line) => {
      const header = /^\s*\[([^\]]+)\]/.exec(line)
      if (header) {
        // `[ workspace.package ]` is valid TOML — trim so the optional inner
        // whitespace does not make the name miss its comparison below.
        table = header[1].trim()
        return line
      }
      if (done || table !== 'workspace.package') {
        return line
      }
      // The trailing capture keeps whatever follows the closing quote: an
      // inline `# comment`, or the `\r` of a CRLF manifest. `\r` is a line
      // terminator, so `.` cannot match it and it needs its own alternative.
      const match = /^(\s*version\s*=\s*")[^"]*(".*\r?)$/.exec(line)
      if (!match) {
        return line
      }
      done = true
      return `${match[1]}${version}${match[2]}`
    })
    .join('\n')
  if (!done) {
    throw new Error('no [workspace.package] version field')
  }
  return bumped
}

/**
 * Rewrite the top-level `"version"` field of a `package.json`.
 *
 * Anchored to the indentation of the manifest's *first* key rather than a
 * hard-coded two spaces, so a tab- or four-space-formatted manifest is bumped
 * too — while a nested `"version"` (inside a dependency or an override block,
 * which is indented deeper) is still never hit. A manifest with no such anchor
 * (minified, or not an object) throws rather than risk the wrong key. Blank
 * lines between the brace and that first key are skipped.
 */
export function bumpPackageJson(text: string, version: string): string {
  const indent = /^\s*\{[^\n]*\n(?:[ \t]*\r?\n)*([ \t]*)"/.exec(text)?.[1]
  const line = indent === undefined
    ? undefined
    : new RegExp(`^${indent}"version"\\s*:\\s*"[^"]*"`, 'm')
  if (!line?.test(text)) {
    throw new Error('no top-level "version" field')
  }
  return text.replace(line, `${indent}"version": ${JSON.stringify(version)}`)
}

/** Every manifest the bump touches, relative to `root`, in bump order. */
export function manifestPaths(root: string): string[] {
  const paths = ['Cargo.toml', 'package.json']
  for (const dir of WORKSPACE_DIRS) {
    let entries: string[]
    try {
      entries = readdirSync(join(root, dir), { withFileTypes: true })
        .filter(entry => entry.isDirectory())
        .map(entry => join(dir, entry.name, 'package.json'))
    }
    catch {
      continue // the workspace root does not exist in this tree
    }
    // Explicit, locale-pinned comparator: the default sort is UTF-16 code-unit
    // order, and an unpinned `localeCompare` would vary with the runner's locale.
    paths.push(...entries.sort((a, b) => a.localeCompare(b, 'en')))
  }
  return paths
}

/**
 * Apply `version` to every manifest under `root`, returning the paths changed.
 *
 * `root` is a parameter rather than the repo root so the rewrite is testable
 * against a fixture directory. The rewrite is all-or-nothing: nothing is
 * written until every manifest has been rewritten successfully.
 */
export function bumpVersion(root: string, version: string): string[] {
  if (!isValidSemver(version)) {
    throw new Error(`not a valid semver version: ${version}`)
  }

  // Every manifest is rewritten and validated in memory before the first write,
  // so a manifest that throws cannot leave the repo half-bumped.
  const pending: { absolute: string, relative: string, bumped: string }[] = []
  for (const relative of manifestPaths(root)) {
    const absolute = join(root, relative)
    let text: string
    try {
      text = readFileSync(absolute, 'utf8')
    }
    catch {
      continue // an optional member (e.g. a bare `apps/*` dir) has no manifest
    }
    const bumped = relative.endsWith('.toml')
      ? bumpCargoToml(text, version)
      : bumpPackageJson(text, version)
    if (bumped !== text) {
      pending.push({ absolute, relative, bumped })
    }
  }

  for (const { absolute, bumped } of pending) {
    writeFileSync(absolute, bumped)
  }
  return pending.map(entry => entry.relative)
}

function fail(message: string): never {
  console.error(`bump-version: ${message}`)
  process.exit(1)
}

async function main(): Promise<void> {
  const version = process.argv[2]
  if (!version) {
    fail('usage: bun scripts/bump-version.ts <version>   (e.g. 0.2.0)')
  }
  if (!isValidSemver(version)) {
    fail(`not a valid semver version: ${version}`)
  }

  const root = join(import.meta.dir, '..')
  const changed = bumpVersion(root, version)
  for (const path of changed) {
    console.log(`bump-version: ${path} → ${version}`)
  }
  if (changed.length === 0) {
    console.log(`bump-version: every manifest is already at ${version}`)
  }

  // Cargo.lock pins the workspace crates by version, so it goes stale the
  // moment the manifest moves. `--offline` keeps the refresh from reaching the
  // network (and from silently pulling unrelated registry updates).
  const update = Bun.spawnSync(
    ['cargo', 'update', '--workspace', '--offline'],
    { cwd: root, stdout: 'inherit', stderr: 'inherit' },
  )
  if (update.exitCode !== 0) {
    console.error('bump-version: could not refresh Cargo.lock offline. Run it yourself:')
    console.error('bump-version:   cargo update --workspace')
    process.exit(1)
  }
  console.log('bump-version: Cargo.lock refreshed')
}

if (import.meta.main) {
  await main()
}
