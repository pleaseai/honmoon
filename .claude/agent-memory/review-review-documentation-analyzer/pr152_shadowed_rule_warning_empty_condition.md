---
name: pr152-shadowed-rule-warning-empty-condition
description: PR #152 (issue #95) shadowed-rule wiki section verified against warn_shadowed_rules/is_unconditional/endpoint_covers; found the "empty condition matches nothing" claim contradicts actual panic behavior and the page's own Fail-closed semantics section
metadata:
  type: project
---

Reviewed `wiki/getting-started/policy-authoring.md` "### Rule order and unreachable rules"
(added by PR #152, issue #95) against `crates/honmoon-core/src/lib.rs`
(`warn_shadowed_rules`, `shadowed_rules`, `is_unconditional`, `endpoint_covers`) and
`crates/honmoon-core/src/engine.rs` (`compile_condition`, `endpoint_matches`).

Verified accurate: `*`-endpoint shadowing-everything claim, endpoint-specific-rule-leaves-`*`
-reachable claim, "only literal `true`" claim, the sample `tracing::warn!` field names/order
(`rule`, `shadowed_by`, `endpoint`), and the citation content itself (the 262-329 range is
merely off by ~1-2 lines at each edge from the true function block 260-330 — minor, not a
correctness issue).

**The one real defect**: the wiki claims "an empty condition is not valid CEL, so such a rule
matches nothing." I confirmed by test (`cel_interpreter::Program::compile("")` under
`catch_unwind`) that it actually **panics** (antlr4rust `unreachable code` at tree.rs:383), and
`engine.rs::compile_condition` does not catch that panic — it only matches `Ok`/`Err`, so an
empty-condition rule that is ever *reached* at evaluation time crashes the process, not "matches
nothing" gracefully. This also contradicts the page's own pre-existing "## Fail-closed semantics"
section, which asserts blanket-graceful non-matching for "a rule whose condition fails to
compile." The `lib.rs` doc comment itself is honest about this (cites issue #151); the wiki
should be too — reported at confidence 80, severity important, category fabricated-content
(comfortable claim not supported by the actual runtime behavior).

**Why worth remembering:** this is the kind of doc/code gap that's easy to miss because the
*load-time* code path (`Policy::from_yaml` → `warn_shadowed_rules`) never calls
`Program::compile`, so a superficial check of only the cited `lib.rs:262-329` range looks fine.
The panic only surfaces later, at rule-evaluation time in `engine.rs`, and only when an
empty-condition rule is actually reached by a request — reviewers must follow the condition
string to where it's compiled, not just where it's parsed.

**How to apply:** for future policy-authoring/CEL docs PRs, check any claim about empty/invalid
CEL condition behavior against `engine.rs::compile_condition` (or wherever `Program::compile` is
actually invoked) rather than the YAML-loading code, since load and evaluation are different
code paths with different error handling.
