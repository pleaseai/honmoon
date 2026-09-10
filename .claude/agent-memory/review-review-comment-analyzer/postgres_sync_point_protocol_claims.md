---
name: postgres-sync-point-protocol-claims
description: PR #112 (issue-101 pipelined-refusal-order) sync-point comments in crates/honmoon-proxy/src/runtime/postgres.rs
metadata:
  type: project
---

honmoon-proxy's postgres.rs runtime (PR #112, issue #101) added a `ClientLink`
sync-point counting barrier (`forwarded`/`delivered` + `REFUSAL_ORDER_TIMEOUT`)
so a locally injected refusal cannot overtake responses to statements the
client pipelined ahead of it. Core mechanics verified accurate against the
code (`forwarded_sync_point()` call sites match the StartupMessage/Q/Sync/
FunctionCall set; `ReadyForQuery`'s 1-byte payload claim is correct; refused
statements leave both counters untouched so they "stay in step" as ADR-0007
claims).

Two prose imprecisions flagged (both moderate confidence, not blocking):
- Comments describing Parse/Bind/Execute as "answered only when Sync arrives"
  / "answered inside somebody else's cycle" conflate the immediate per-message
  ack (ParseComplete/BindComplete/CommandComplete, sent before Sync) with the
  deferred ReadyForQuery sync-point. Terminate gets no response at all, ever.
- The claim that a Sync sent mid-COPY is "the one" message whose sync point
  the backend "legitimately swallows" is an unverified/likely-inaccurate PG
  protocol claim (mid-copy Sync is a protocol violation → error, not a
  silent legitimate swallow), with no test/citation backing it.

**Why:** these are the kind of assertion the reviewer instructions asked to
verify against the real PG v3 protocol; worth re-checking if this file's
sync-point comments are touched again.
**How to apply:** when reviewing further changes to postgres.rs's sync-point
barrier, re-verify these two spots didn't get corrected/re-introduced, and
apply the same "answered vs. counted-as-sync-point" precision lens to any
new comments there.
