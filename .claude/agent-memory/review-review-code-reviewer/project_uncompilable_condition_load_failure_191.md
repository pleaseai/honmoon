---
name: project-uncompilable-condition-load-failure-191
description: "PR #197 (issue #191) makes an uncompilable CEL rule condition a Policy::from_yaml load failure instead of a warn-and-load-anyway; the code review found nothing, but two findings the code pass missed landed from the comment and docs angles — both fixed in-PR"
metadata:
  type: project
---

PR #197 (issue #191), `crates/honmoon-core/src/{lib,engine}.rs` — completes the lineage started by
#154/#164/#167: since `cel` 0.14 no longer panics on a malformed condition (only returns `Err`),
the objection to load-time rejection (#154: "moves the panic from request time to startup") no
longer applies, so `Policy::from_yaml` now refuses to load a policy with any rule whose `condition`
does not compile (`Error::UncompilableRuleConditions`, naming every offending rule by index/name/
condition text, not just the first).

**The code pass found nothing — and two real findings still landed.** Both came from angles a
correctness read does not cover, which is the thing to remember: (1) `program_for`'s new doc
justified an unreachable match arm with a caller that does not exist ([[pr197-program-for-dead-arm]]);
(2) the error rendered the author's `name` and `condition` between backticks, so a condition made
only of invisible characters — one of the very classes the change exists to catch — printed as an
empty pair of backticks. Both fixed before merge; the second by rendering both values with `{:?}`.

**Why the correctness read itself came back clean:**
- `from_yaml` order is `validate_endpoints → validate_rules → warn_undefined_endpoints →
  warn_shadowed_rules → CompiledConditions::compile → validate_compiled_conditions`. The two
  warnings can fire on a policy that ultimately fails to load (they're about *other* rules and
  stay true) — this is explicit and intentional per the doc comment on `from_yaml`, not a bug.
- `CompiledConditions::compile` stopped warning; `warn_inert_rule` is still reachable, but only via
  `compile_condition`/`program_for` for a `Policy` built in code (not through the loader) or a
  `Rule::condition` reassigned after load — the loader path now reports via
  `validate_compiled_conditions` instead.
- `inert_rules` changed from `Vec<&Rule>` to `Vec<(usize, &Rule)>`; the index comes from
  `.enumerate()` over the same slice the filter runs on, so pairing can't drift.
- `UncompilableRule` is a new public type but not `Serialize` and not part of the `Policy` struct
  (the `compiled` field is `#[serde(skip)]`) — no TD-001 (Rust+TS+JSON-Schema sync) violation.
- Three modified tests in engine.rs + two in lib.rs were checked against the old versions: none
  weakened — each pins the inverted behaviour deliberately (load fails now, or asserts the
  intermediate `CompiledConditions::compile` table directly where `from_yaml` can no longer
  produce one for an uncompilable condition).
- All `lib.rs:` / `engine.rs:` line-range citations in the three wiki files matched the actual
  post-diff line numbers when checked with `grep -n`; `wiki/llms-full.txt` (generated) mirrors the
  two source wiki files' hunks exactly.
- `cargo test -p honmoon-core --lib` (224 passed at the final head) and `cargo clippy -p honmoon-core --all-targets
  -- -D warnings` both clean.

See also [[project_agents_md_rules]] for the Ask-first list this stayed clear of (no new dep, no
`decide()` precedence change, and the policy-struct-shape change is derived/skip-serialized so it
doesn't trigger TD-001).
