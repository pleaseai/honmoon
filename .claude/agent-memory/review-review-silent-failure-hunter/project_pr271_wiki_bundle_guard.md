---
name: pr271-wiki-bundle-guard
description: "scripts/check-wiki-bundle-current.ts holds wiki/llms-full.txt byte-identical to its pages — the verdict is byte equality only, and the generator's entry-point guard plus both error branches are the parts that had to be made fail-loud and testable in #271"
metadata:
  type: project
---

`scripts/check-wiki-bundle-current.ts` (issue #258) holds `wiki/llms-full.txt` byte-identical to
the pages `wiki/.vitepress/gen-llms-full.mjs` renders, closing the "page edited without
regenerating the bundle" gap.

**The load-bearing separation.** `compareBundle()`'s verdict is `actual === expected` and nothing
else; the page-list diff, the per-page stale diff and the fallback only choose the *message*, and
`bundleSections()` (imported from `check-wiki-source-anchors.ts`) is used for attribution alone.
If a later change ever lets a parse decide the verdict, a mis-parsed `<doc>` boundary can turn a
stale bundle into a pass. That separation is the thing to re-check when this file is touched.

**Three fail-silent paths review found here, all closed in #271 — do not re-report them:**

- `invokedAsScript()` in the generator wrapped both `realpathSync` calls in a bare
  `catch { return false }`. A throw during a genuine direct invocation would have made the
  generator write nothing, print nothing and exit 0 — the exact staleness this checker exists to
  catch, one level up. Now the plain `resolve(argv[1]) === self` comparison is tried first, so an
  ordinary run is decided with no filesystem call, and the remaining catch (reachable only once
  the paths already differ) logs to stderr.
- `checkRepository()`'s two error branches were reachable by no test. Mutation-proven: replacing
  the render-catch with `return []`, and faking a successful read in the read-catch, each left the
  whole file green — so a deleted bundle reported as current. `checkRepository` now takes an
  injectable `Sources` pair and both branches have tests.
- The "importing the generator writes nothing" test was vacuous: the test file's own static import
  had already run before the test body captured the baseline, so a restored top-level write would
  have been invisible to it. Both directions are now driven as subprocesses, and each validates
  the other's mtime signal.

**What is still not covered**, so this is not cited as more than it is: that the generator lists
the right pages is #270, and whether a page's content is *correct* is nobody's here — a wrong
sentence is copied faithfully into a bundle this calls current.
