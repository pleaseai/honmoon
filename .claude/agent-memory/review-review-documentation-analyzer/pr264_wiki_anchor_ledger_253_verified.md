---
name: pr264-wiki-anchor-ledger-253-verified
description: >-
  PR #264 (issue #253) repointed all 30 remaining #253 wiki anchors and re-attributed the other
  5 to #260/#261/#263 — every repointed range was independently re-resolved against the branch
  content and found accurate (source range matches the sentence/table-row it supports), zero
  findings from this pass — but greptile caught one the pass missed, an unsupported "schema"
  in a Guards cell whose citation the PR had just repointed, corrected before merge; read that
  as the calibration point rather than as a clean-PR one
metadata:
  type: project
---

PR #264 closed issue #253 by repointing the 30 remaining stale `#L` source anchors the
`TRACKED` ledger in `scripts/check-wiki-source-anchors.ts` carried against it (honmoon-core
and honmoon-mgmt `lib.rs`, protocols.rs, gateway.rs, auth.ts, index.ts→routes.ts, Cargo.toml,
ADR-0002, product.md, workflow.md, business-model.md, README.md — `main.rs` is *not* among
them: its citation shares a table row with one that was repointed and only looks changed in
the diff), and re-attributing the other 5: to #260 for `egress-gateway.md`'s hand-rolled-proxy
prose, superseded by ADR-0003 and `mitm.rs::host_gate`; to #261 for `protocol-parsing.md`'s
pre-`sqlparser` `DROP MATERIALIZED VIEW` claim, which the test it cites now asserts the
opposite of; and to #263 for `roadmap-open-core.md`'s phase table, one phase behind
`docs/roadmap.md` since Phase 5 (PII / DLP) was inserted — "Isolation modes" is Phase 6, not 5.

I independently re-resolved every one of the 30 repointed anchors against the branch's actual
file content (`cat -n` / `sed -n` on each cited range) against the sentence or table cell it
supports, and found all 30 accurate — including the trickier multi-anchor ones: the k8s
`namespaces`/`nodes` test-assertion rows, `parse_sql_extracts_verb_and_table` cited from two
pages with the same new range, and the `honmoon-mgmt::lib.rs` route handler ranges narrowed to
exactly the named function body. Ran `bun scripts/check-wiki-source-anchors.ts` (932 resolve, 10
known-stale left to #119/#169/#192/#260/#261/#263, matching the PR body) and `bun test` on the
script's own test file (63 pass) — both green. Also independently re-verified all three deferred
groups (#260/#261/#263) against current source and confirmed the deferral reasoning is correct
in each case (functions genuinely don't exist / test now asserts the opposite / phase numbering
genuinely off), not something that could have been repointed honestly instead.

`wiki/llms-full.txt` was regenerated correctly — every changed anchor's new form appears in the
bundle in sync with the page. The `TRACKED` ledger's own doc comment and the new "nothing is
still deferred to #253" test both match the ledger as this PR leaves it (5 entries, 3 issues).

Zero findings from this pass, and that is the part worth keeping. greptile found one this
pass did not: the `Test coverage` row for `parse_sql_extracts_verb_and_table` on
`protocol-parsing.md` listed its Guards as `quoting, schema, case`, and the range the PR had
just repointed it to (`protocols.rs:1728-1734`) has no schema-qualified input at all — the
schema case lives in `parses_postgres_truncate_and_select` (`protocols.rs:1041-1053`,
`SELECT * FROM public.orders` → `orders`), which that table does not cite at all. Corrected to
`quoting, case` before merge.

The lesson generalises past this PR: **repointing a citation makes the cell around it
checkable for the first time**, so a claim that was merely unverifiable before becomes wrong
on the new range. Resolving the range against the prose is not enough — resolve every clause
of the prose against the range, including a comma-separated list in a table cell, where each
item is its own claim. This pass checked that each range supported its row and stopped there.

A second lesson, from getting the follow-up wrong before getting it right: the *replacement*
line numbers quoted in a reply, an issue comment or a commit message are claims under exactly
the same rule as the ones in the page. Four of them were asserted here from a half-remembered
grep and three were wrong — including the name of the test holding the schema case. Re-derive
every number before it leaves the worktree, the same way the page's own anchors are.

See [[pr254-wiki-anchor-drift-fix-verified]] for the sibling PR on `policy-authoring.md`, and
[[line-anchors-drift-from-your-own-commits]] (global memory) for the general pattern this whole
ledger exists to catch.
