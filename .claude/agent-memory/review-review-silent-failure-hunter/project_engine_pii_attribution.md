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

**The one real gap found:** `eval_condition` logs `tracing::warn!` on *compile* failure but
is completely silent on *execution* errors (`program.execute()` returning `Err`, e.g. index
out-of-bounds on `pii.types[0]` or division by `pii.count`) — `matches!(.., Ok(Bool(true)))`
discards the `Err` with zero logging. This was already true pre-PR#108 for the single real
call, but `pii_caused()`'s second (pii-cleared) call newly makes this consequential: an
execution error on the *cleared* re-check inverts to `pii_caused() == true`, silently
folding "condition legitimately needs the real pii value" and "condition has an unrelated
runtime bug" into the same "skip and audit as would-be" bucket, with no log to tell them
apart. See the finding filed against PR #108 for detail — worth checking if a future PR
adds execution-error logging to `eval_condition` (would resolve this).
