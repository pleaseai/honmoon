---
name: pii-attribution-pattern
description: How honmoon-core's detect-mode PII attribution (decide_pii_audit_only) proves fail-closed safety
metadata:
  type: project
---

Issue #99 fix (crates/honmoon-core/src/engine.rs) replaced "re-decide whole policy with pii
cleared" with per-rule attribution: `decide_with` walks rules against REAL facts always: it only
skips (continue) a matched non-Allow rule when `pii_caused(rule, facts)` — i.e. the same rule's
condition, re-evaluated with the pii summary cleared, would NOT match. Allow-verdict matches are
never second-guessed.

**Why this can't fail open:** both `decide_explained` (block) and `decide_pii_audit_only` (detect)
walk the same real facts. They can only diverge at a rule that (a) matches on real facts, (b) is
non-Allow, and (c) would not match with pii cleared — at exactly that point audit-only continues
to the next rule instead of returning. So the enforced verdict is always something the real
policy would also produce (never an ad-hoc weaker one), and any independent (non-pii-dependent)
deny/pause later in rule order still applies.

**How to apply:** when reviewing changes to this function or new PiiWeight variants, check unit
tests exist for: (1) a pii-based allow/exemption before an independent deny — must not swallow
the deny, (2) a genuinely pii-caused deny followed by an independent rule — that rule must still
decide, (3) a pii-caused allow — must not be held back (block and detect must agree). All three
existed for the #99 fix's PR (crates/honmoon-core/src/engine.rs tests + crates/honmoon-proxy/tests/mitm.rs).
