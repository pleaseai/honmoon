---
name: pr137_degraded_decision_variant
description: PR #137 (issue #131) added Decision::Degraded; README/rustdoc/TS types updated correctly but wiki docs describing the Decision enum or "every verdict" audit semantics went stale
metadata:
  type: project
---

PR #137 added `Decision::Degraded` (honmoon-core::audit) for recording a fallback hook-salt
key as an audit event, plus `honmoon hook --audit-log`/`HONMOON_AUDIT_LOG`. Verified accurate:
`packages/claude-plugin/README.md` new sections, `crates/honmoon-cli/src/hook.rs` rustdoc,
`crates/honmoon-core/src/audit.rs` rustdoc, `packages/policy/src/index.ts` `Decision` type,
dashboard `DecisionBadge`/`format.ts`/CSS, `packages/api/src/audit.ts` DECISIONS array, and the
timestamp-ordering/process-local-ids claim in `packages/api/src/audit.ts` (pre-existing, still
correct) — 0 findings across the touched files.

The diff did NOT update two wiki docs that enumerate the `Decision` values or describe
`--audit-log` semantics, both now stale:
- `wiki/deep-dive/control-plane.md` — `Decision (allowed/denied/paused/approved/rejected)` type
  table is missing `degraded`.
- `wiki/deep-dive/egress-gateway.md` — gateway flag table describes `--audit-log` as "Append
  every verdict to a JSONL file"; the gateway now also writes non-verdict `Degraded` events to
  the same file via `hook::record_machine_key_source` at startup.
- `docs/roadmap.md` line 101 similarly says "Local audit log (every verdict, structured)".

**Why:** these are exactly the "Decision::Degraded makes existing docs inaccurate" pattern the
task brief calls out by name — good calibration example for future PRs touching `Decision`/audit
enums: always grep wiki + roadmap for enumerations of the Decision variants or "every verdict"
phrasing when a new non-verdict Decision variant is added.

**How to apply:** for any future PR adding an audit `Decision` variant, check
`wiki/deep-dive/control-plane.md`, `wiki/deep-dive/egress-gateway.md`, and `docs/roadmap.md` for
Decision enumerations / "every verdict" claims even if the diff doesn't touch them — this repo's
wiki lags code changes to shared enums.
