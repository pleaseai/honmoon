---
name: policy-compiled-conditions-table
description: "How honmoon compiles CEL rule conditions at policy load (#167/PR #193) — the text-keyed CompiledConditions table, why a miss is not an error, and the four staleness/growth questions already answered so they are not re-derived"
metadata:
  type: project
---

`Policy::from_yaml` builds a private `compiled: engine::CompiledConditions`
(`HashMap<String, Option<Arc<Program>>>`) after `validate_endpoints`/`validate_rules`;
`decide_with` calls `program_for(policy, rule)` instead of compiling per evaluation.

**Why:** CEL parsing used to run once per endpoint-matching rule per request. Once, not twice — a
rule reaching `pii_caused` was compiled a single time and its `Program` reused, so it is
`eval_program` that runs twice there, never the compiler. (The "twice" count belongs to evaluation
and is attached to compilation in issue #167's own body; do not carry it forward.)

**How to apply — these were traced once, do not re-derive them:**

- *Staleness:* the table is keyed by the condition **text**, not rule index or name. `Rule::condition`
  is `pub`; a reassigned condition simply misses the table and `program_for` compiles it. A hit can
  only ever be the program for that exact string, so two rules sharing a condition legitimately
  share one `Arc<Program>`.
- *Miss path:* not an error. Code-built and plain-`serde`-deserialized policies carry an empty table
  and behave exactly as before the change (compile + warn at evaluation). Misses are **not**
  inserted, so the table cannot grow past the distinct conditions of the loaded document.
- *Thread safety:* `Arc<Program>` re-executed for the attribution pass is fine — see
  [[cel-compile-panic-class]] for the `execute(&self)` / no-interior-mutability evidence. An
  `assert_send_sync::<Policy>()` test pins it.
- *Serialization:* `#[serde(skip)]`, so the ASTs never reach the YAML/JSON shapes or
  `GET /api/policy` (`honmoon-mgmt` `PolicyResponse`), and a `Debug` impl prints the entry count
  rather than the trees.
- *Fail-closed:* a condition that fails to compile is recorded as `Some(None)`; the rule stays inert
  and cannot turn a deny default into an allow. Load still succeeds — refusing such a policy is
  tracked separately.

The only behaviour actually moved is *when* the "failed to compile" `tracing::warn!` fires: once
per inert **rule** at load, instead of on every evaluation of that rule. Per rule, not per distinct
condition — `CompiledConditions::compile` dedups the compile but warns from `inert_rules(rules)`,
so two rules sharing one unusable condition are both named. Deduping the warning too was the
first-draft bug on PR #193: the second rule went inert with nothing in any log naming it, because
the table answered for it from then on and it never reached the compiler again. The asymmetry that
gives it away is that `warn_undefined_endpoints` and `warn_shadowed_rules`, the loader's other two
"a rule of yours is inert" warnings, are both per rule.

The CLI initializes `tracing_subscriber` (`honmoon-cli/src/main.rs:262`) before any
`Policy::from_yaml`, so the load warning is not swallowed by ordering — but
`EnvFilter::from_default_env()` with `RUST_LOG` unset drops `warn`, which was equally true of the
per-evaluation warning. That an inert rule is only ever a log line, never a load failure, is
tracked as #191.
