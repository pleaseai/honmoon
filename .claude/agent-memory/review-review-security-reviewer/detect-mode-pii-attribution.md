---
name: detect-mode-pii-attribution
description: How honmoon detect mode attributes verdicts to PII (decide_pii_audit_only) and the two invariants to re-check on any change there
metadata:
  type: project
---

Detect mode (`PiiMode::Detect`) does not re-decide the policy on cleared facts; it walks the
rules once against real facts and skips a matching rule when the verdict is non-Allow *and*
the rule would not have matched with the PII summary cleared (`engine.rs::pii_caused`).
A PII-caused **Allow** is not held back while nothing else has been — but is once a verdict
has already been held back, since block mode never reached it.

**Why:** the promise is "content scanning never blocks", not "detect mode bypasses the policy" —
endpoint/k8s/HTTP-metadata rules must still enforce in detect mode.

**How to apply:** when this area changes, re-check two invariants that the skip model can break:
1. a PII-caused Allow reached *after* a skipped rule masking a later non-PII deny/pause — that
   allow was dead code in block mode, so it must not grant anything. Closed in PR #108 by the
   `held_back` disjunct; `a_pii_caused_allow_behind_a_held_back_rule_does_not_mask_later_rules`
   guards it;
2. skipping a PII-caused Pause can expose a later non-PII Deny, making detect *stricter* than
   block. Accepted and documented on `decide_pii_audit_only` since PR #108: the guarantee is
   Allow-preservation (block allows ⇒ detect allows), not monotonic severity.
Fail-closed is preserved: a condition that fails to compile or errors evaluates to `false`, so the
rule never matches in the main walk and `pii_caused` (which negates `eval_program` re-run with
the summary cleared, and requires `facts.pii.is_some()`) is never reached for it. Since PR #108
`eval_condition` is split into `compile_condition` + `eval_program`, so the program is compiled
once per rule and reused for the attribution re-run.
