---
name: pr271-wiki-bundle-guard-verified
description: "The #258 bundle-currency repro and the mechanical facts behind it — repointing an anchor needs BOTH the link text and the URL moved or a different rule fires, and the module doc's mutation counts are reproducible rather than decorative"
metadata:
  type: project
---

PR #271 closed issue #258 with `scripts/check-wiki-bundle-current.ts`, holding
`wiki/llms-full.txt` byte-identical to the pages `wiki/.vitepress/gen-llms-full.mjs` inlines. Its
module doc is dense with checkable claims, and they were reproduced rather than read. The facts
worth keeping:

- **The repro needs both halves of the citation moved.** Repointing
  `getting-started/policy-authoring.md`'s `lib.rs#L57-L152` to `#L57-L151` and leaving the bundle
  alone reproduces the #258 gap exactly: `check-wiki-source-anchors.ts` exits 0 with "1098
  citation(s) resolve" while `check-wiki-bundle-current.ts` fails naming that page's section.
  Changing only the URL and not the link text trips a *different* rule (the text/URL disagreement,
  rule 4) and so does not demonstrate the gap. If you are re-deriving this, move both.
- The bundle was independently confirmed already in sync at `cfcaf0b` — clone, regenerate, diff
  byte-identical — so the PR needed no regeneration commit.
- `compareBundle`'s "empty if and only if byte-identical" property is mutation-checkable: deleting
  the fallback `return` fails exactly 4 of the file's 22 tests (the header, missing-newline,
  appended-byte and extra-spacing cases), which is the four that reach that branch. The other two
  of the six "iff" fixtures reach the page-list and stale-section branches instead — the list
  probes three branches, not six.
- **The `^#[0-9]` ATX-heading-lint trap has a smaller blast radius here than it looks.** Asked of
  the tool rather than inferred from the ignore globs (`eslint . --format json`), eslint lints
  exactly 16 markdown files: the repo-root `AGENTS.md`, `ARCHITECTURE.md`, `CLAUDE.md`,
  `PRODUCT.md`, `README.md`, `docs/*.md`, and the per-package `AGENTS.md`/`CLAUDE.md`/`README.md`.
  Both `wiki/**` *and* `.claude/agent-memory/**` are ignored, so a `#123` wrapping to column 1 in
  a wiki page or a memory note is not a lint failure. Check a specific file with
  `bunx eslint <file>` — a "File ignored because of a matching ignore pattern" warning is the
  answer — rather than reasoning from `eslint.config.mjs`'s `ignores` list, which does not name
  `.claude/` at all yet still excludes it.

**On the review itself, so this is not read as a clean bill of health:** the documentation angle
found nothing, but other finders on the same PR did — a false symmetry claim in the `chunks()`
JSDoc, two mutation-proven untestable error branches, and a vacuous import-side-effect test. All
were fixed before merge. A doc review returning zero findings says the prose matched the code it
described; it says nothing about whether that code was right.

**Calibration point:** a module doc that makes reproducible, falsifiable claims (repro commands,
mutation counts, byte-diffs) rewards literally running them over reading them. Every claim in this
one held — which is exactly why the defects that did exist were in the parts the doc did *not*
make a claim about.
