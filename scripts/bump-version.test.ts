import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { bumpCargoToml, bumpPackageJson, bumpVersion, isValidSemver, manifestPaths } from './bump-version'

const CARGO_TOML = `[workspace]
resolver = "2"
members = ["crates/honmoon-cli"]

[workspace.package]
version = "0.1.0"
edition = "2024"

[workspace.dependencies]
honmoon-core = { path = "crates/honmoon-core" }
serde = { version = "1", features = ["derive"] }
`

function packageJson(name: string): string {
  return `{
  "name": ${JSON.stringify(name)},
  "type": "module",
  "version": "0.1.0",
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}
`
}

let root: string

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'honmoon-bump-'))
  writeFileSync(join(root, 'Cargo.toml'), CARGO_TOML)
  writeFileSync(join(root, 'package.json'), packageJson('honmoon-mono'))
  for (const member of ['packages/policy', 'apps/dashboard']) {
    mkdirSync(join(root, member), { recursive: true })
    writeFileSync(join(root, member, 'package.json'), packageJson(`@honmoon/${member.split('/')[1]}`))
  }
})

afterEach(() => {
  rmSync(root, { recursive: true, force: true })
})

describe('isValidSemver', () => {
  test('accepts release and pre-release versions, rejects the rest', () => {
    expect(['0.2.0', '1.0.0-rc.1', '1.2.3+build.5'].every(isValidSemver)).toBe(true)
    expect(['v0.2.0', '0.2', '1.2.3.4', '', 'latest'].some(isValidSemver)).toBe(false)
  })

  test('rejects leading zeroes in numeric pre-release identifiers, allows them in build metadata', () => {
    // cargo refuses `1.0.0-01`, so accepting it here would rewrite every
    // manifest and only then fail, leaving the workspace half-bumped.
    expect(['1.0.0-01', '0.2.0-rc.01'].some(isValidSemver)).toBe(false)
    expect(['1.0.0-0', '1.0.0-0a', '1.2.3+01'].every(isValidSemver)).toBe(true)
  })
})

describe('bumpCargoToml', () => {
  test('rewrites only the [workspace.package] version line', () => {
    const bumped = bumpCargoToml(CARGO_TOML, '0.2.0')
    expect(bumped).toContain('[workspace.package]\nversion = "0.2.0"')
    // The `version` inside [workspace.dependencies] is a dependency requirement.
    expect(bumped).toContain('serde = { version = "1", features = ["derive"] }')
    expect(bumped.split('\n').length).toBe(CARGO_TOML.split('\n').length)
  })

  test('matches a table header written with inner whitespace', () => {
    const bumped = bumpCargoToml(CARGO_TOML.replace('[workspace.package]', '[ workspace.package ]'), '0.2.0')
    expect(bumped).toContain('version = "0.2.0"')
  })

  test('keeps an inline comment and a CRLF line ending on the version line', () => {
    const source = CARGO_TOML.replace('version = "0.1.0"', 'version = "0.1.0" # keep me\r')
    expect(bumpCargoToml(source, '0.2.0')).toContain('version = "0.2.0" # keep me\r')
  })

  test('throws when [workspace.package] carries no version line', () => {
    const source = CARGO_TOML.replace('version = "0.1.0"\n', '')
    expect(() => bumpCargoToml(source, '0.2.0')).toThrow('no [workspace.package] version field')
  })
})

describe('bumpPackageJson', () => {
  test('rewrites the top-level version and leaves formatting intact', () => {
    const bumped = bumpPackageJson(packageJson('honmoon-mono'), '0.2.0')
    expect(bumped).toContain('  "version": "0.2.0",')
    expect(bumped).toContain('    "left-pad": "^1.3.0"')
    expect(bumped.endsWith('}\n')).toBe(true)
  })

  test('rewrites a manifest indented with tabs or four spaces', () => {
    for (const indent of ['\t', '    ']) {
      const source = `{\n${indent}"name": "x",\n${indent}"version": "0.1.0"\n}\n`
      expect(bumpPackageJson(source, '0.2.0')).toBe(`{\n${indent}"name": "x",\n${indent}"version": "0.2.0"\n}\n`)
    }
  })

  test('derives the anchor past blank lines after the opening brace', () => {
    const source = '{\n\n  "name": "x",\n  "version": "0.1.0"\n}\n'
    expect(bumpPackageJson(source, '0.2.0')).toContain('  "version": "0.2.0"')
  })

  test('leaves a deeper-nested version key alone', () => {
    const source = '{\n  "name": "x",\n  "overrides": {\n    "version": "9.9.9"\n  },\n  "version": "0.1.0"\n}\n'
    const bumped = bumpPackageJson(source, '0.2.0')
    expect(bumped).toContain('    "version": "9.9.9"')
    expect(bumped).toContain('  "version": "0.2.0"')
  })

  test('throws when there is no top-level version field', () => {
    expect(() => bumpPackageJson('{\n  "name": "x"\n}\n', '0.2.0')).toThrow('no top-level "version" field')
  })
})

describe('manifestPaths', () => {
  test('lists Cargo.toml, the root manifest, and every workspace member', () => {
    expect(manifestPaths(root)).toEqual([
      'Cargo.toml',
      'package.json',
      'packages/policy/package.json',
      'apps/dashboard/package.json',
    ])
  })
})

describe('bumpVersion', () => {
  test('bumps every manifest and reports what changed', () => {
    const changed = bumpVersion(root, '0.2.0')
    expect(changed).toEqual([
      'Cargo.toml',
      'package.json',
      'packages/policy/package.json',
      'apps/dashboard/package.json',
    ])
    for (const relative of changed) {
      const text = readFileSync(join(root, relative), 'utf8')
      expect(text).toContain('0.2.0')
      expect(text).not.toContain('"0.1.0"')
    }
  })

  test('is idempotent — a re-run reports no changes', () => {
    bumpVersion(root, '0.2.0')
    expect(bumpVersion(root, '0.2.0')).toEqual([])
  })

  test('rejects a non-semver version before writing anything', () => {
    expect(() => bumpVersion(root, 'v0.2.0')).toThrow('not a valid semver version')
    expect(readFileSync(join(root, 'package.json'), 'utf8')).toContain('"version": "0.1.0"')
  })

  test('writes nothing when a later manifest fails', () => {
    // `packages/policy` is bumped after Cargo.toml and the root manifest, so a
    // non-atomic rewrite would leave those two ahead of the rest.
    writeFileSync(join(root, 'packages/policy/package.json'), '{\n  "name": "@honmoon/policy"\n}\n')
    expect(() => bumpVersion(root, '0.2.0')).toThrow('no top-level "version" field')
    expect(readFileSync(join(root, 'Cargo.toml'), 'utf8')).toContain('version = "0.1.0"')
    expect(readFileSync(join(root, 'package.json'), 'utf8')).toContain('"version": "0.1.0"')
  })
})
