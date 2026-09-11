---
name: project-hook-salt-fallback-visibility-131
description: PR #137 (issue #131) — reviewed clean; the Overview.tsx decision-mix gap found mid-review was closed before merge
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

**Found mid-review and closed before merge — do not re-report it.** An earlier round of this
review flagged that `apps/dashboard/src/components/Overview.tsx`'s `DecisionMix` widget computed
`total = allowed + denied + paused` and omitted `degraded`. The merged PR reconciled it:
`Overview.tsx:301` now totals `allowed + denied + paused + degraded` and `:306` renders a
"Degraded guarantees" row. Verify against the file before treating any part of this note as an
open gap.

**The durable lesson is the reconciliation, not the gap.** Adding a `Decision` variant touches
more than the badge that renders one event: any widget that sums decisions into a total has to
take the new variant too, or the percentages silently exclude it while every individual event
still displays correctly. `DecisionBadge` looked complete on its own, which is exactly why the
omission survived to review — check the aggregates, not just the per-event rendering.

See also [[project_hook_salt_parity_98]] for the earlier PR #122 that this one builds on
(`machine_key()` return type changed from `Vec<u8>` to `MachineKey { bytes, source }`).
