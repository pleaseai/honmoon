---
name: engine-pii-audit-monotonicity
description: 'honmoon-core decide_pii_audit_only can produce a stricter verdict than block mode when a PII-caused non-Allow rule is skipped and a later, unrelated, stricter rule matches — the guarantee is Allow-preservation only, stated in the rustdoc since PR #108'
metadata:
  type: project
---

`crates/honmoon-core/src/engine.rs` `decide_with`/`decide_pii_audit_only` (added in PR #108,
issue #99, detect-mode attribution): skipping a PII-caused rule with a non-`Allow` verdict makes
the walk continue to later rules that block mode's first-match semantics never reach. If a later,
unrelated rule (matching only on endpoint/k8s/http facts) has a *stricter* verdict than the
skipped one (e.g. skipped rule is `pause`, later rule is `deny`), `decide_pii_audit_only` returns
the stricter verdict even though `decide`/`decide_explained` (block mode) on the same facts would
have returned the milder one. Confirmed empirically with a scratch test:
policy `[pause-on-pii (endpoint '*', condition pii.count>0), deny-prod-delete (endpoint k8s-prod,
condition k8s.verb=='delete')]` on facts with both k8s delete and PII present → block mode = Pause,
`decide_pii_audit_only` = Deny.

The one guarantee that *does* hold universally: if block mode's outcome is `Allow`, detect mode's
outcome is also `Allow` (an `Allow`-verdict rule is never skipped, so the first-match result is
identical whenever it's `Allow`). The broader phrasing in the rustdoc ("detect mode can never deny
something block mode would let through") and in a test comment ("Holding PII back must never *add*
a restriction") overclaims beyond that narrow Allow-preservation property — reported as a
review-comment-analyzer finding in the PR #108 review, not yet fixed as of 2026-09-11.

**Why:** this is a hotspot — the module has an explicit "detect mode is a promise about the
scanner, not a bypass for the rest of the policy" design intent, and future edits to rule-skip
logic in `decide_with` should re-check this specific ordering-escalation case, not just the
Allow-preservation case the current tests cover.

**How to apply:** when reviewing future changes to `engine.rs`'s PII-attribution logic or its
doc comments, check whether "detect mode never adds restriction" is stated as an unqualified
global guarantee — it isn't true; only the Allow-specific case is.
