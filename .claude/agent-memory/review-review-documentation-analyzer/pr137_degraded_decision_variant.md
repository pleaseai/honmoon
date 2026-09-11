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

An earlier round of this review found three docs left stale by the diff. **All three were
updated before merge — they are correct now, so do not re-report them:**
- `wiki/deep-dive/control-plane.md:165` — the `Decision` type table now lists `degraded`, and
  `RedactionFacts` is documented alongside it.
- `wiki/deep-dive/egress-gateway.md:233` — `--audit-log` now reads "Append every verdict — and
  any recorded security degradation — to a JSONL file".
- `docs/roadmap.md:101` — now "every verdict plus recorded security degradations".

**Why:** these are exactly the "Decision::Degraded makes existing docs inaccurate" pattern the
task brief calls out by name — good calibration example for future PRs touching `Decision`/audit
enums: always grep wiki + roadmap for enumerations of the Decision variants or "every verdict"
phrasing when a new non-verdict Decision variant is added.

**How to apply:** for any future PR adding an audit `Decision` variant, check
`wiki/deep-dive/control-plane.md`, `wiki/deep-dive/egress-gateway.md`, and `docs/roadmap.md` for
Decision enumerations / "every verdict" claims even if the diff doesn't touch them — this repo's
wiki lags code changes to shared enums.
