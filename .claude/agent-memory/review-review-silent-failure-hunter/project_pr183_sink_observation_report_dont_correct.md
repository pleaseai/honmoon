---
name: pr183-sink-observation-report-dont-correct
description: 'PR #183 (issue #161) added AuditLog::with_file sink-exposure observation (mode/foreign-owner/hard-link) as Decision::Degraded events via existing `record`, which already logs-and-continues on sink write failure; reviewed clean, no new silent-failure defects'
metadata:
  type: project
---

PR #183 (`crates/honmoon-core/src/audit.rs`) made `open_sink` return `(File, Metadata)`
and added `observe_sink`/`sink_exposure`, which turn the already-performed `fstat` into
0-3 `Decision::Degraded` events (`audit-sink-exposed`, `audit-sink-foreign-owner`,
`audit-sink-hard-linked`) recorded via the existing `AuditLog::record` before
`with_file` returns. `record` already swallowed a sink-write failure with
`tracing::warn!` before this PR (unchanged code, not a new gap) — see
[[pr163-open-sink-hardening]] and [[hook-salt-audit-visibility-131]] for why that design
is accepted (short-lived `honmoon hook` process, no durable channel otherwise).

Reviewed the full diff (audit.rs, lib.rs, the new `tests/audit_sink_exposure.rs`,
`packages/policy/src/index.ts`, `apps/dashboard/src/format.ts`) — no silent failures,
no swallowed errors introduced, no inappropriate fallback. Every acceptance
(report-don't-correct, non-unix no-op, nlink==0 unlinked-file exclusion) is documented
in doc comments and pinned by tests. Callers (`main.rs`, `hook.rs`) untouched by this
PR, so their `with_file` error handling was out of scope.

**How to apply:** if a future PR touches `observe_sink`/`sink_exposure`/`record` again,
re-verify the write-failure swallow in `record` still logs with `tracing::warn!` (that
warning is the gateway's channel only — `honmoon hook` has no `RUST_LOG`, so `EnvFilter`
drops it there, issue #131, and the hook's own salt record goes through `record_durable`
for that reason) and that the report-vs-refuse framing hasn't quietly flipped to a
`set_permissions`/refusal call, which the project memory
`.claude/agent-memory/review-review-security-reviewer/audit-sink-residual-gaps.md`
would flag as a regression on the security side, not this agent's.
