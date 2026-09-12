---
name: pr193-cel-compile-at-load-diagram
description: "A rewritten Mermaid diagram is a claim surface of its own — on PR #193 the deep-dive sequence diagram's alt-branch labels contradicted the prose two paragraphs above them while every prose claim checked out, so check each branch label against the paragraph preceding it, not only the prose against the code"
metadata:
  type: feedback
---

Reviewing the `wiki/deep-dive/policy-engine.md` and `wiki/getting-started/policy-authoring.md`
rewrites on PR #193 (issue #167, CEL conditions compiled at load), every prose claim checked out
against `crates/honmoon-core/src/engine.rs` and `lib.rs`. The defect was in the **diagram**.

The deep-dive prose said, correctly, that a reassigned condition "misses the table and is compiled
on the spot" and that a `Policy` built in code "carries no table and compiles at evaluation". The
Mermaid diagram two paragraphs below collapsed both into one branch — `no program (inert, or built
in code)` → `rule does not match` — which asserts a code-built policy's rule can only fail to
match. `program_for`'s miss arm calls `compile_condition` and can return a program, and the PR's
own test `a_loaded_policy_compiles_each_distinct_condition_once_at_load` builds a `Policy` in code
with a valid condition and asserts it decides `Deny`.

**Why:** a diagram is not a picture of the prose. Rewriting one forces simplification choices the
surrounding paragraphs never had to make — collapsing two branches into one, naming a case the
prose left general — and each choice is a fresh claim that can be wrong while every sentence around
it is right. Checking the prose against the code does not cover it.

**How to apply:** read each `alt` / `else` branch label as its own sentence and check it against
the paragraph immediately preceding the diagram *and* against the code, especially any branch that
names a case (`built in code`, `inert`, `first request`) rather than describing a condition. A
branch that merges two paths the prose distinguishes is the shape to look for.

**Both defects this note came from were fixed on the same PR before merge** — the diagram now
separates the hit and miss paths, and a citation that overshot its cited test by ~20 lines into the
next one was narrowed. Do not re-report either against current `main`.

Deliberately no line-anchor list here: an earlier draft recorded which `engine.rs#L…` citations
"checked out", and later commits on the same PR shifted every one of them. Wiki line anchors rot on
any insertion above them — that is #192 — so a memory note that blesses a specific anchor set
manufactures false confidence on the next review. See [[policy-compiled-conditions-table]] for the
mechanism the pages describe.
