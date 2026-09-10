---
name: detect-mode-pii-attribution
description: How honmoon detect mode attributes verdicts to PII (decide_pii_audit_only) and the two invariants to re-check on any change there
metadata:
  type: project
---

Detect mode (`PiiMode::Detect`) does not re-decide the policy on cleared facts; it walks the
rules once against real facts and skips a matching rule when the verdict is non-Allow *and*
the rule would not have matched with the PII summary cleared (`engine.rs::pii_caused`).
PII-caused **Allow** verdicts are deliberately not held back.

**Why:** the promise is "content scanning never blocks", not "detect mode bypasses the policy" —
endpoint/k8s/HTTP-metadata rules must still enforce in detect mode.

**How to apply:** when this area changes, re-check two invariants that the skip model can break:
1. a PII-caused Allow reached *after* a skipped rule short-circuits the walk and can mask a later
   non-PII deny/pause (that allow was dead code in block mode, so it should not grant anything);
2. skipping a PII-caused Pause can expose a later non-PII Deny, making detect *stricter* than
   block — the opposite of the documented invariant.
Fail-closed is preserved: a condition that fails to compile or errors evaluates to `false`, so the
rule never matches in the main walk and `pii_caused` (which negates `eval_condition`) is never
reached for it.
