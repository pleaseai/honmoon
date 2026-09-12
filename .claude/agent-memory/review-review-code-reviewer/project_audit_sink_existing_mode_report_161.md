---
name: project-audit-sink-existing-mode-report-161
description: 'PR #183 (issue #161) — an existing audit sink keeps its permissive mode/foreign owner/hard link but AuditLog::with_file now reports each as a Decision::Degraded event off the fstat open_sink already performs; reviewed clean, all doc-comment claims verified against code and tests'
metadata:
  type: project
---

`open_sink` (`crates/honmoon-core/src/audit.rs`) now returns `(File, Metadata)` instead of
just `File`, so `observe_sink`/`sink_exposure` report `audit-sink-exposed` (`mode & 0o077
!= 0`), `audit-sink-foreign-owner` (`uid != geteuid()`), `audit-sink-hard-linked` (`nlink
> 1`) off the same `fstat` the type-check already used — no second syscall, no TOCTOU
window. Each fires independently (verified in `sink_exposure_reports_each_observation_independently`,
including all three firing together). `AuditLog::with_file` records these via `self.record`
before returning, ahead of anything the caller records — confirmed by tracing `next_id`
(starts at 1) and `recent()`'s newest-first reversal against
`an_existing_sink_keeps_the_mode_it_had`'s assertion that `recent(10)[1].id == 1`.

**Doc claims checked against code, all true:**
- "the hook opens the sink only when it has a degraded key to report" — `hook.rs`'s
  `audit_machine_key_status` returns early on `!status.is_degraded()`, before
  `AuditLog::with_file` is ever called.
- "before the salt event, in the same file" (README) — `with_file` records the sink
  observation(s) synchronously inside the constructor, then `record_machine_key_status`
  runs on the already-constructed `audit` handle afterward.
- "the observation is written to the sink itself" — exercised end-to-end in the new
  public-API test `crates/honmoon-core/tests/audit_sink_exposure.rs`.

Reviewed clean: builds, `cargo clippy -p honmoon-core --all-targets` clean, all
honmoon-core audit tests and the new integration test pass, dashboard `format.test.ts`
passes. The security-reviewer's [[project_audit_sink_nofollow_138]] /
[[project_audit_sink_symlinked_parent_160]] chain continues here — item 4 from that
memory (an untrusted plain-directory component, accepted with no event) is explicitly
left open by this PR, not silently dropped; the doc comment and the rewritten
`audit-sink-residual-gaps.md` both say so.
