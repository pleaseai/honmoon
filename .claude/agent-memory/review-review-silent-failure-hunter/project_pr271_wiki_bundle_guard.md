---
name: pr271-wiki-bundle-guard
description: PR #271 (issue #258) check-wiki-bundle-current.ts + gen-llms-full.mjs refactor — compareBundle's byte-equality verdict is airtight (tested "iff" property); the one real gap is invokedAsScript()'s bare `catch { return false }` around realpathSync, which would make the generator no-op silently and exit 0 if it ever fires during a genuine direct invocation
metadata:
  type: project
---

Reviewed PR #271 (issue #258): `scripts/check-wiki-bundle-current.ts` (new) holds
`wiki/llms-full.txt` byte-identical to the pages `wiki/.vitepress/gen-llms-full.mjs`
renders, closing the "page edited without regenerating the bundle" silent-failure gap.

**Verified sound:**
- `compareBundle()` — verdict is `actual === expected`; everything else (page-list
  diff, per-page stale diff, fallback) only chooses the *message*. The test file
  (`check-wiki-bundle-current.test.ts`) has an explicit "is empty if and only if
  the two are byte-identical" property test covering header change, missing
  trailing newline, byte appended after last section, extra spacing, no sections
  at all, and an unterminated section — all assert `length > 0`. No path returns
  `[]` on differing input.
- `checkRepository()` — catches `renderBundle()` and `committed()` errors and
  converts both to `Problem`s (never a pass); `committed()`'s read failure also
  always surfaces as a finding, never silently treated as "file is current."

**One real gap, not fully covered by tests:** `invokedAsScript()` in
`gen-llms-full.mjs` does
```js
try { return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url)) }
catch { return false }
```
If `realpathSync` throws while the file genuinely *is* being run as a script
(exotic but possible: permission error, filesystem race, symlink issue on the
script's own path), the guard swallows it, returns `false`, and the entry-point
`if` never fires — the generator does nothing, prints nothing, exits 0. That is
exactly the "contributor believes they regenerated" silent failure this PR
exists to prevent, now potentially reintroduced one level up. Low likelihood
(direct `bun`/`node` invocation almost always makes `realpathSync(argv[1])`
succeed) but no test exercises this catch branch and impact would be severe if
it ever fires. Recommend logging to stderr (and/or exiting non-zero) in the
catch rather than silently returning false.

Secondary, lower-confidence nit: both `checkRepository()`'s `renderBundle()`
catch and `committed()`'s catch cast with `(error as Error).message`; a
non-Error throw would render `undefined` in the finding text. Fs errors are
almost always real `Error` instances so this is low-likelihood, minor severity.

If this file is touched again: re-check whether `invokedAsScript()`'s catch
gained a log statement, and whether `bundleSections()` (imported from
`check-wiki-source-anchors.ts`, unmodified by this PR) is still only used for
message attribution and not for the pass/fail verdict — that separation is
what keeps a mis-parsed `<doc>` boundary from ever turning a stale bundle into
a pass.
