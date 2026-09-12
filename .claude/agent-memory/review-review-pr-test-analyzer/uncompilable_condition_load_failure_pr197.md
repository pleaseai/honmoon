---
name: uncompilable-condition-load-failure-pr197
description: "PR #197 (issue #191) makes an uncompilable rule condition a load failure; the five modified tests were checked and none is weakened, and program_for's `Some(None)` cache-hit arm — unreachable via from_yaml since #191 — is pinned by a test that writes the table by hand"
metadata:
  type: project
---

## What changed

`Policy::from_yaml` (crates/honmoon-core/src/lib.rs) used to compile every rule condition, warn
about the ones that failed, and load the policy anyway. Since #191/PR #197 it calls
`validate_compiled_conditions()` after compiling and refuses to load
(`Error::UncompilableRuleConditions`, naming every offending rule by index/name/condition) if any
rule's condition does not compile. A blank condition is still caught earlier by `validate_rules`
(`Error::BlankRuleCondition`) and never reaches the compile step.

## The five modified tests: verified not weakened

- `engine.rs::a_loaded_policy_compiles_each_distinct_condition_once_at_load` — old asserted
  `compiled.len() == 2` on a loaded policy with one malformed rule (2 distinct conditions: the
  shared POST one and `"&&"`). New version drops the malformed rule from the *loaded* policy
  (replaced with a third distinct-but-valid `GET` condition, so `compiled.len() == 2` still holds)
  and separately asserts the `Some(None)` failed-compile-table shape via a direct
  `CompiledConditions::compile(&[...])` call (not through `from_yaml`, since such a policy can no
  longer load). Same ground, split because the combination is no longer producible via the loader.
- `engine.rs::both_rules_sharing_an_unusable_condition_are_accounted_inert` — old called
  `Policy::from_yaml` then `decide()` on the *loaded* policy. New version can't do that (the policy
  would be refused), so it calls `CompiledConditions::compile(&rules)` directly to assert
  `inert_rules` (same per-rule accounting + dedup-count assertions as before), then separately
  builds a `Policy { rules: rules.to_vec(), ..Default::default() }` (not through `from_yaml`, so
  its private `compiled` field is the empty default) and asserts `decide()` fails closed. Verdict
  matches the old test, but note the code path differs — see below.
- `engine.rs::a_condition_that_does_not_compile_still_loads_and_only_its_own_rule_goes_inert` →
  renamed `..._fails_the_load_for_the_whole_policy` — inverted to `expect_err`, checks the
  `UncompilableRuleConditions` shape, then re-tests the same YAML with the condition repaired to
  confirm both rules load and decide. Correctly-inverted test, not a weakening.
- `lib.rs::the_two_code_points_the_schema_mirror_turns_on` — the U+FEFF half used to assert the
  policy loads (not blank, but unevaluable until request time); now asserts
  `Error::UncompilableRuleConditions` since compiling now happens at load. Correct inversion.
- `lib.rs::accepts_a_rule_whose_condition_has_content` doc comment — only the comment changed to
  mention the new compile check; the loop body/assertions (`"true"`, `"sql.verb == 'DROP'"`,
  `" true "`) are untouched (all three are valid CEL, so they never trip the new check).

All five hold up under `git show origin/main:...` diffing; ran `cargo test -p honmoon-core --lib`
against the PR head — 224 passed, none touching this.

## The `Some(None)` hit arm: unreachable via the loader, but pinned

`program_for`'s `Some(compiled) => compiled.clone()` arm in engine.rs handles a **hit** on a
previously-recorded compile failure (`Some(None)`). Before #191 that arm fired for any rule in a
*loaded* policy whose condition didn't compile (the loader warned and loaded anyway). Since #191,
`from_yaml` only ever returns a `Policy` when `inert_rules` is empty, so **no policy that
`from_yaml` hands back can ever contain a `Some(None)` entry in its `compiled` table** — the arm is
dead code for anything built through the public loader. It's only reachable if crate-internal code
directly constructs a `Policy` with `compiled` pre-populated (the field is private but visible to
descendant modules of the crate root, so `engine.rs`'s own tests *could* do this) — and no test
does. `both_rules_sharing_an_unusable_condition_are_accounted_inert`'s final `decide()` assertion
goes through the **miss** arm (`compile_condition` fallback, recompiling on the spot) instead, which
returns the same `Verdict::Deny` but exercises different code. This isn't a coverage regression
worth blocking a PR over — the hit-with-failure state is now unreachable via any consumer in this
repo — **Closed before merge:** PR #197 added
`engine.rs::a_recorded_compile_failure_in_the_table_declines`, which writes `policy.compiled` by
hand (the field is private but visible to descendant modules of the crate root, so `engine.rs`'s
own tests can), asserts the lookup *hits* on `Some(None)`, and asserts `decide()` still answers
`Deny`. So a future change that reintroduces a path populating `compiled` outside `from_yaml`, or
that "cleans up" the arm as provably unreachable, does have a test that catches it. `program_for`'s
doc was rewritten in the same PR to say the arm has no live caller rather than implying one — see
[[pr197-program-for-dead-arm]].

## Fixture check

Searched crates/honmoon-proxy/tests, crates/honmoon-mgmt/tests, crates/honmoon-cli/tests,
crates/honmoon-core/benches for `condition:` literals as of PR #197 — all are valid CEL (no `&&`,
`()`, blank, or lone-symbol conditions). None needed fixing for this PR.
