---
name: pr254-wiki-anchor-drift-fix-verified
description: >-
  PR #254 (issue #204) repointed 27 stale source-citation anchors on policy-authoring.md and added
  scripts/check-wiki-source-anchors.ts — all 27 were independently re-resolved against the file
  content and found accurate, so do not re-verify that page's anchors; the one open nit is the
  rules[] overview row, deliberately left alone
metadata:
  type: project
---

PR #254 fixed issue #204's anchor drift on `wiki/getting-started/policy-authoring.md` by repointing
27 `#L` source citations (lib.rs, engine.rs, main.rs, index.ts, policy.schema.json, cli/index.ts,
agent.yaml) to match the current file content, regenerated `wiki/llms-full.txt` to match, and added
`scripts/check-wiki-source-anchors.ts` (with `.test.ts`) to make it a `bun test`-enforced invariant.

I independently re-resolved all 27 citations against that branch's content (`sed -n` on each cited
range) and found every one accurate to the sentence or table cell it supports, with one exception
below. **Do not re-derive that verification** — re-resolve only anchors a later commit could have
moved, which the checker now answers mechanically anyway.

The one nit, raised and deliberately not fixed: the `rules[]` row of the overview table cites
`lib.rs:144-152`, the `Rule` struct, which carries "protocol-aware" in its doc comment but says
nothing about *ordering*. The `pub rules: Vec<Rule>` field on `Policy` sits elsewhere and has no
doc comment about ordering either, and "the first rule whose endpoint matches … wins" is cited
separately later on the page (`engine.rs:102-138`). The pattern predates #254 — the same design
carried the older, worse anchor `lib.rs:109-117` — and #204 put rewriting the prose out of scope,
so the row was left as written. Raising it again is re-raising a judged call, not a new finding.

The three `engine.rs` anchors this page deliberately leaves stale (`56-64`, `59-60`, `48-50`) belong
to issue #169, which tabulates exactly those three ranges on this page. Only `59-60` trips the new
checker, and it is in that script's `TRACKED` ledger against #169.

**Caution about this note's own vintage.** It was written mid-PR, against the revision the review
read, and later commits in the same PR rewrote the checker's module doc comment and its ledger
(`Tracked.pages` became part of the match, and two rules about the *scan* were added). Claims here
are about the wiki page, which did not change again; nothing here describes the script's internals,
deliberately, because that is the half that moved. Read the script, not this note, for what it
enforces.

See [[line-anchors-drift-from-your-own-commits]] (global memory) for the general pattern.
