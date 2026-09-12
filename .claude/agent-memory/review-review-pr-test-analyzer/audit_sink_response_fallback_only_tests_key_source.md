---
name: audit-sink-response-fallback-only-tests-key-source
description: "PR #182's audit_machine_key_status response-message tests (a_refused_sink_is_reported_rather_than_swallowed, a_planted_symlink_at_the_sink_cannot_suppress_the_degradation) only exercise unusable_salt_dir (MachineKeySource::Fallback) — the SaltExposure::Open/WasOpen degradation() branches are still only exercised through record_machine_key_status's JSONL path, never through the new response-message path; also neither response test asserts the reason= segment's content."
metadata:
  type: project
---

In crates/honmoon-cli/src/hook.rs (PR #182, issue #165), `degradation()` has three
branches: fallback/unpersisted key_source, and two `SaltExposure` (Open/WasOpen)
branches. The new response-carrying path (`audit_machine_key_status` returning
`Option<String>`, formatted with `rule=... key_source=... reason=... sink=...
sink_error=...`) is only tested via `unusable_salt_dir`, which always produces
`MachineKeySource::Fallback`. The Open/WasOpen exposure branches remain tested
only through `record_machine_key_status`'s durable-JSONL path (pre-existing
tests around line ~1400-1700), not through the response-message formatting
path this PR added. Also, neither new response test (`a_refused_sink_is_...`,
`a_planted_symlink_...`) asserts the `reason=` segment's content — only
`rule=`, `key_source=`, `sink=`, and presence of `sink_error=` are checked.

**Why:** if `degradation()`'s exposure-branch data (key_source=persisted,
rule=hook-salt-exposed/-was-exposed) were miswired into the response format
string, no test would catch it — every response test independently derives a
Fallback status.

**How to apply:** when reviewing this file, this is a real but low/moderate-
severity gap (same code path is exercised for JSONL, and `key_source_label`'s
correctness is independently pinned by
`the_response_spells_key_source_the_way_the_audit_event_does`) — report at
confidence ~40-55, not higher, since the format-string plumbing itself is
simple and the individual pieces (label mapping, rule constants) are each
tested elsewhere.
