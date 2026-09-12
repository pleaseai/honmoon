---
name: audit-sink-response-fallback-only-tests-key-source
description: "hook.rs response-fallback tests (issue #165): each degradation() branch must reach audit_machine_key_status's Option<String> through a refused sink, and reason= must be asserted whole — the gap found on PR #182 was closed in-PR; re-check when a branch is added"
metadata:
  type: project
---

In `crates/honmoon-cli/src/hook.rs` (issue #165, PR #182) `degradation()` is the one
classifier behind two channels: the durable JSONL record (`record_machine_key_status`) and
the hook-response `systemMessage` (`audit_machine_key_status` returning `Option<String>`,
formatted `rule=… key_source=… reason=… sink=… sink_error=…`). Mid-review the response
path was exercised only through `unusable_salt_dir` (always `MachineKeySource::Fallback`),
so the two `SaltExposure` branches (`hook-salt-exposed` / `hook-salt-was-exposed`,
`key_source=persisted`) reached the response format string untested, and no test read
the `reason=` segment.

Both were closed in the same PR: `an_exposed_key_refused_by_the_sink_is_reported_with_its_own_rule`
drives `MachineKeyStatus::persisted(Some(SaltExposure::Open|Closed))` through a refused
sink and asserts `rule=`, `key_source=persisted` and `reason=` verbatim, and
`a_refused_sink_is_reported_rather_than_swallowed` asserts `reason=` equals the loader's
own string.

**Why:** the response exists precisely when the JSONL record did not land, so it is the
one channel with nothing else to cross-check against; a branch that reaches it only via
the JSONL tests would be untested where it matters.

**How to apply:** when a `degradation()` arm or a field in the response format string is
added, look for a test that drives that arm through `audit_machine_key_status` with a
refused sink and asserts the new field's content — not just its presence. Absent that,
report at confidence ~45; do not re-report the PR #182 gap, it is closed.
