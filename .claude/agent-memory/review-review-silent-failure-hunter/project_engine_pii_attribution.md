---
name: project-engine-pii-attribution
description: honmoon-core engine.rs per-rule PII attribution (decide_pii_audit_only) design and its one real gap
metadata:
  type: project
---

`crates/honmoon-core/src/engine.rs` (PR #108, issue #99) refactored detect-mode's PII
downgrade from "re-decide the whole policy with `pii: None`" (which could let an
earlier, unrelated allow-rule win and turn a deny into an allow — the bug #99 was about)
to a per-rule `pii_caused()` check inside a single walk (`decide_with` /
`decide_pii_audit_only`): a rule that matches real facts but wouldn't match with `pii`
cleared is skipped (not returned), and the walk continues to later rules. This design was
verified carefully and is sound for the cases explored:
- Compile failures can't cause misclassification: `Program::compile` is deterministic on
  the condition string alone, so if the first (real-facts) eval already failed to compile,
  the rule never matches and `pii_caused` is never invoked.
- Non-pii-referencing rules can't be misclassified as PII-caused via an execution error,
  because the only input that differs between the two `eval_condition` calls is the `pii`
  variable — `http`/`sql`/`k8s` context is identical, so an unrelated field access errors
  identically both times (and thus never reaches `pii_caused`, since the first call would
  already have failed to match).
- Verdict::Allow rules are deliberately never skipped, so detect mode can't become *more*
  restrictive than block mode by skipping past an Allow into a later Deny.
- `mitm.rs`'s `pii.filter(|p| p.count > 0)` audit gate is provably always-true when `pii`
  is `Some`, because `summarize_spans` (the only constructor) returns `None` for empty
  spans — never `Some(count: 0)`. Not a bug, just redundant.
- Non-HTTP proxy paths (`socks.rs`, `runtime/postgres.rs`) call `decide_explained` directly
  without the audit-only holdback, but never populate `Facts.pii` at all, so there's no
  behavioral divergence from `decide_pii_audit_only` there (no content scanning happens
  outside the MITM HTTP path).

**The gap that was found and closed (PR #108):** the evaluator logged `tracing::warn!` on
*compile* failure but was silent on *execution* errors (`program.execute()` returning `Err`,
e.g. index out-of-bounds on `pii.types[0]`), and `matches!(.., Ok(Bool(true)))` discarded the
`Err`. `pii_caused()`'s pii-cleared re-check made that consequential: an execution error on
the cleared run inverts to `pii_caused() == true`, folding "needs the real pii value" and
"has an unrelated runtime bug" into the same skip-and-audit bucket. `eval_program` (the
post-#108 name; `eval_condition` was split into `compile_condition` + `eval_program`) now
logs it at `tracing::debug!` — deliberately not `warn`, because referencing a fact the
request does not carry is an error *by design* (that is how a `sql` rule declines an HTTP
request), so a warn-level line would fire on ordinary traffic.
