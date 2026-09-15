---
name: wiki-anchor-checker-path-boundary
description: >-
  scripts/check-wiki-source-anchors.ts takes its file path out of a markdown link but bounds the
  read correctly via realPathInside — traversal, leading slash, %2e%2e, backslash, NUL, symlink-out
  and in-repo FIFO were all measured as refused, so do not re-report the #233 class here; the
  ANCHOR backtracking that was the one live residue was bounded, and BUNDLE_DOC measured, before PR
  #254 merged
metadata:
  type: project
---

`scripts/check-wiki-source-anchors.ts` (PR #254) parses `[text](https://github.com/pleaseai/honmoon/blob/<ref>/<path>#L..)`
out of every document `wikiDocuments()` returns and opens `<path>`. `readCited` hands
`join(REPO_ROOT, path)` to `realPathInside(REPO_ROOT, …)` from `check-dashboard-csp.ts`, handles
all three non-`path` outcomes (`missing`, `reason`, read failure) and opens the *resolved* path.

Measured once (2026-09-15, macOS) — each of these is refused, so do not re-derive or re-report them:

- `../../../../../../etc/passwd` → `resolves to /private/etc/passwd, outside the build directory`
- a leading-slash path (`/etc/passwd`) — `join`, not `resolve`, so it stays under the root and reports missing
- `%2e%2e/…`, `..%2f…`, `..\..\…` — never decoded, so they are literal filenames
- a NUL in the path — `realpathSync` throws `ERR_INVALID_ARG_VALUE` inside the try, reported as `did not resolve`
- an in-repo symlink to `/etc/passwd`, and a symlinked *directory* component — both resolve outside and are refused
- an in-repo FIFO — refused by the `statSync().isFile()` half, so `readFileSync` never blocks

Content disclosure through the findings is bounded incidentally: the only cited-file text echoed into
CI output is a line matching `BARE_DELIMITER` (`^[)\]}]+[,;]?$`).

The backtracking residue this note originally pointed a future reviewer at **was closed inside the
same PR**, so do not report it either. `ANCHOR`'s link-text group was `[^\]]*`, which retried every
`[` in the document and scanned to end-of-input before failing — 200 KB of bare `[` measured 47.9 s.
It is `[^\]\n]{0,200}` now, and the same input measures 99 ms. What is left, named in that regex's
own doc comment: 200 KB of a *partial* prefix (`[x](https://github.com/pleaseai/`…) still measures
1.7 s, because each attempt fails inside the URL literal rather than inside the text group. That is
superlinear, small, bounded by the CI job limit, and the text bound is not what would fix it.

`BUNDLE_DOC` (`/^<doc\s[^>]*\bpath="([^"]+)"/`, added after review to attribute an `llms-full.txt`
citation to the page it was generated from) is the one regex added beside `ANCHOR`, and it was
measured too: it is `^`-anchored behind a literal `<doc` + whitespace, applied per line, and 200 KB
single-line inputs shaped as `path=` bait, an unterminated run, and an unterminated quote all
measure under 1 ms. It opens no path of its own — the page name it yields is compared against
`Tracked.pages`, never joined onto the filesystem.

**Why:** #233 filed exactly this class (CWE-59/CWE-22) against the dashboard guards, so every new
build-time script that opens a path it did not write draws the same review.
**How to apply:** the path boundary and the text-group bound are both settled — read them as
answered rather than re-measuring. A finding worth raising here is one about a path this file opens
*without* `realPathInside`, or a new regex added beside `ANCHOR`. See [[dashboard-shell-csp]] for the
sibling guard.
