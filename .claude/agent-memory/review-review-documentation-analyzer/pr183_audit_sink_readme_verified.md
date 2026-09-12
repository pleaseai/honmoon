---
name: pr183-audit-sink-readme-verified
description: "PR #183 (issue #161) added audit-sink-exposed/foreign-owner/hard-linked degraded events; packages/claude-plugin/README.md's ordering claim (sink events before the salt event, same file), the hook-only-when-degraded scoping claim, and the gateway-reports-every-start claim were all verified accurate against audit.rs/hook.rs — a clean-PR calibration point"
metadata:
  type: project
---

PR #183 (issue #161) made `AuditLog::with_file` report a loose-mode/foreign-owner/hard-linked
audit sink as `Decision::Degraded` events (`audit-sink-exposed`, `audit-sink-foreign-owner`,
`audit-sink-hard-linked`) carrying `FactsSummary.sink: { path, reason }`.

Three README claims in `packages/claude-plugin/README.md` were checked line-by-line against
`crates/honmoon-core/src/audit.rs` and `crates/honmoon-cli/src/hook.rs` and all held:

- "before the salt event, in the same file" — `AuditLog::with_file` calls `observe_sink` and
  `log.record(draft)` synchronously (writes are ordered, ring lock released before file I/O)
  *before* returning, and `hook.rs::audit_machine_key_status` chains
  `with_file(...).and_then(|audit| record_machine_key_status(...))`, so the sink observation(s)
  are always written first when both occur.
- "the hook opens the sink only when it has a degraded key to report" — confirmed:
  `audit_machine_key_status` early-returns `if !status.is_degraded()` before ever calling
  `AuditLog::with_file`, and `record_machine_key_status` never hits its `return Ok(())`
  no-op arm when `is_degraded()` is true (the only arm that skips writing a salt event
  requires `Persisted, None`, which is exactly the case `is_degraded()` excludes) — so a sink
  observation is never written without a paired salt event on the hook transport.
- "the gateway reports them at every start" — `main.rs` calls `AuditLog::with_file`
  unconditionally whenever `--audit-log` is configured, unlike the hook's guarded call site.

The `find <dir> -samefile <log>` remedy for the hard-linked case works on both GNU find and
macOS/BSD find (both support `-samefile`).

**Why:** the ordering/scoping claims looked like exactly the kind of confident-specifics that
[[docs-completeness-claim-unbounded-review]] flags as needing verification, but here they
were grounded in code the diff actually shows (`with_file`'s internal call order, the
`is_degraded()` guard) rather than invented — worth recording as a positive calibration
point alongside [[pr122_hook_salt_parity]] and [[pr137_degraded_decision_variant]].

**How to apply:** if a future PR touches `with_file`'s internal ordering or
`audit_machine_key_status`'s guard, recheck these three claims — they are load-bearing on
exactly that code path.
