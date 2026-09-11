---
name: project-hook-salt-fallback-visibility-131
description: PR #137 (issue #131) — reviewed clean; documents the Overview.tsx decision-mix gap left by adding Decision::Degraded
metadata:
  type: project
---

PR #137 added `Decision::Degraded` + `RedactionFacts` (`crates/honmoon-core/src/audit.rs`),
`MachineKey`/`MachineKeySource` provenance (`crates/honmoon-cli/src/hook.rs`), `--audit-log` /
`HONMOON_AUDIT_LOG` on `honmoon hook`, a startup record in `gateway()`
(`crates/honmoon-cli/src/main.rs`), the `append_jsonl` single-`write_all` fix, and mirrored TS wire
types (`packages/policy/src/index.ts`, `packages/api/src/audit.ts`) + dashboard rendering
(`DecisionBadge.tsx`, `format.ts`, `index.css`). Traced every call site end to end, ran
`cargo check`/`clippy -D warnings`/`cargo test -p honmoon-cli hook::` and `bun test
packages/api/src/audit.test.ts` — all clean. No compile errors, no logic errors, no guideline
violations found.

**Gap worth flagging on a future touch (not this PR's scope)**: `apps/dashboard/src/components/
Overview.tsx`'s `DecisionMix` widget computes `total = allowed + denied + paused` and does not
include `degraded` in that breakdown (it does show up fine in `LatestDecisions` via
`DecisionBadge`, and in `?decision=degraded` audit queries). Not a bug — the widget is
self-consistent — but a degraded event is invisible from the "Decision mix" percentages on the
Overview page. Flag only if a future PR's stated goal is dashboard-wide degradation visibility;
this PR's stated scope was "record it in the audit log," which it does.

See also [[project_hook_salt_parity_98]] for the earlier PR #122 that this one builds on
(`machine_key()` return type changed from `Vec<u8>` to `MachineKey { bytes, source }`).
