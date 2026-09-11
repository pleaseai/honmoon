---
name: shadowed-rules-self-shadow-gap
description: honmoon-core's shadowed_rules() (issue #95) reports an unconditional rule as shadowed by an earlier one, and attributes to the *first* shadower — both pinned by a test in PR #152, so do not "clean up" either
metadata:
  type: project
---

`Policy::shadowed_rules()` in crates/honmoon-core/src/lib.rs iterates every rule and checks only
whether an *earlier* rule is unconditional and covers its endpoint. It never excludes the current
rule from being reported as shadowed, even when that rule is *also* unconditional — so two
`condition: "true"` rules in a row on the same endpoint report the second against the first. That
is correct (the second really is unreachable), and it is deliberate: adding a
`!is_unconditional(&rule.condition)` guard would silently stop reporting a duplicated
connection-allow.

Raised during the PR #152 review as an untested path, together with the docstring's claim that a
rule is "reported once, against the *first* rule that shadows it". Both are now pinned by
`a_shadowed_rule_is_reported_against_the_first_rule_that_shadows_it`, which stacks two
unconditional rules ahead of a statement deny and asserts all three names.

**Why:** stacking two `condition: "true"` allows is what a policy author does while iterating, and
the attribution promise is load-bearing for the warning being actionable — it names the rule that
actually answers the request, not the nearest duplicate.

**How to apply:** when reviewing future changes to the shadowed-rule diagnostic, check that test
still holds. A refactor that skips unconditional rules as shadow *targets*, or that replaces
`.find()` with a last-match search, breaks it — and both look like harmless cleanups in a diff.
