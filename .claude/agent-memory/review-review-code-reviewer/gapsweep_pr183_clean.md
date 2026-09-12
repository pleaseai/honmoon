---
name: gapsweep-pr183-clean
description: 'Gap sweep of PR #183 (issue #161): checked ring/capacity interaction in hook.rs with_file(1, ...), open_sink call sites, recent()/id ordering, TS/dashboard mirror, mgmt API serialization — found nothing beyond the pre-identified list'
metadata:
  type: project
---

Targeted gap sweep for [[project_audit_sink_existing_mode_report_161]], specifically
checking angles a top-down read misses: ring capacity interaction, invariant breaks,
error paths, call sites of the changed `open_sink` signature.

Checked and ruled clean:
- `crates/honmoon-cli/src/hook.rs:521` uses `AuditLog::with_file(1, path)` (ring
  capacity 1). The observation(s) `with_file` records internally, plus the caller's
  own `record_machine_key_status` call, all still hit the file via `record`/
  `record_durable` regardless of ring capacity — the ring only bounds what
  `recent()`/`len()` can see in-memory, never what's appended to the JSONL sink. No
  data loss, matches existing (pre-#161) capacity semantics.
- Only one caller of `open_sink` (`with_file` itself) — the `(File, Metadata)`
  signature change is fully contained, builds clean.
- All other `AuditLog::with_file` callers (honmoon-mgmt e2e, honmoon-proxy mitm
  tests, hook_transports.rs) use `AuditLog::new` (in-memory only) — no sink,
  no observation possible, unaffected.
- `recent()` returns newest-first (`ring.events.iter().rev()`); the
  `an_existing_sink_keeps_the_mode_it_had` test's `recent(10)[1].id == 1` is
  consistent with that (index 0 = caller's later event, index 1 = the earlier
  observation) — not an off-by-one, despite looking like one on first read.
- `packages/policy/src/index.ts` / `apps/dashboard/src/format.ts` mirror is
  complete and consistent; `honmoon-mgmt`'s `GET /api/audit` handler returns
  `Json<Vec<AuditEvent>>` via serde derive, so the new `sink` field propagates
  over the wire with no manual serialization to update.
- Concurrent-create test (`concurrent_opens_of_one_new_sink_all_succeed`,
  8 threads x 3 rounds) unaffected: honmoon-created files land owner-only, so
  `sink_exposure` never fires there.

No new findings; this diff is a genuinely clean, additive change.
