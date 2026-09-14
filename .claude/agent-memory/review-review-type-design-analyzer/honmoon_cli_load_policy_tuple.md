---
name: honmoon-cli-load-policy-tuple
description: "honmoon-cli's load_policy returns (Policy, String) on purpose — the source text is served at GET /api/policy and a second read would reopen a TOCTOU window; do not re-raise 'use a named struct' or 'return only Policy'"
metadata:
  type: project
---

`crates/honmoon-cli/src/main.rs::load_policy(&Path) -> Result<(Policy, String)>`
is the single policy read for `run --policy`, `gateway --config` and
`policy validate` (PR #217 / issue #202). The `String` is the exact source text
`gateway` hands to `AppState::with_hook_config` (honmoon-mgmt takes
`impl Into<String>`, so it is moved, not cloned), from where its only reader is
`get_policy` — `GET /api/policy`, the dashboard's read-only policy view. Despite the
constructor's name, nothing on the hook endpoint reads it. The other two callers bind
`let (policy, _) = …`.

**Why:** returning only `Policy` would make `gateway` read the file a second
time — a second read means a TOCTOU window between the text that was validated
and the text that is served, which is exactly the class of bug #202 is about.
A named struct or a split pair of functions buys nothing at three call sites and
the project's guidelines are explicit about YAGNI / minimal code. The two
elements have distinct types, so the pair cannot be transposed silently.

**How to apply:** in a type-design review of this file, do not report the tuple
shape, the discarded `String`, or the by-value `String` return (three
once-at-startup call sites) as findings. The shape guard
(`not_a_policy_document`) is enforced inside `load_policy` and `Policy::from_yaml`
has no other production caller in the crate — enforcement is centralized, though
strictly by convention rather than by a compiler barrier, since `from_yaml` stays
public in honmoon-core. Flag that only if a new in-crate call site actually
bypasses `load_policy`.
