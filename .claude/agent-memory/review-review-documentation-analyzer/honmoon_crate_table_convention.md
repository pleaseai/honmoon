---
name: honmoon-crate-table-convention
description: honmoon repo names honmoon-core's public engine functions explicitly in AGENTS.md/ARCHITECTURE.md crate tables — new public decide-family functions should be checked against these tables
metadata:
  type: project
---

Honmoon's `AGENTS.md` (root and `crates/AGENTS.md`) and `ARCHITECTURE.md` both describe
`crates/honmoon-core/src/engine.rs` by explicitly naming its public functions, e.g.
"Policy model, `decide_explained()` engine (CEL + egress)". When a PR adds a new public function
to `honmoon-core::engine` (exported from `lib.rs`), check whether these two docs' function lists
should be updated — they are written as an enumerated list, not a representative example, so a
new decision entry point (e.g. `decide_pii_audit_only` added for PR #108 / issue #99, per-rule PII
attribution for detect mode) is a plausible omission worth flagging, though at moderate rather
than high confidence since the tables are terse summaries rather than API references.

**Why:** Reviewed for issue #99 (detect-mode PII attribution) and confirmed the doc-comment on the
new function itself was thorough and accurate; the only friction was the crate-summary tables not
mentioning the third function by name.

**How to apply:** When `crates/honmoon-core/src/lib.rs`'s public re-exports change, diff against
`AGENTS.md` / `crates/AGENTS.md` / `ARCHITECTURE.md` crate-table rows for `honmoon-core` and flag at
~50-60 confidence if the new symbol isn't named. Also check `crates/honmoon-proxy/src/gateway.rs`
separately from `mitm.rs` — gateway.rs (raw CONNECT tunnel) does not call any `decide*` function
directly, so ARCHITECTURE.md's claim that gateway.rs decides "via `decide_explained()`" was already
questionable before this PR and is a pre-existing/out-of-scope issue, not something this diff
introduced.
