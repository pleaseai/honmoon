---
name: honmoon-approval-hold-docs
description: Drop-guard doc comments in crates/honmoon-proxy/src/approval.rs (CancelOnDrop) describe only the external future-drop trigger; PR #109 added a second, internal early-return trigger (hold_until's abandoned select! arm) without updating them.
metadata:
  type: project
---

`crates/honmoon-proxy/src/approval.rs`'s `CancelOnDrop` struct doc (and the
comment directly above where the guard is constructed inside `hold_until`)
say the guard fires "if the holding future is dropped ... the caller's future
is dropped when the waiting client disconnects." That description matches
`hold()`'s mechanism (mitm.rs / HTTP path: the whole `hold()` future is
externally dropped by the caller when its connection closes).

PR #109 (issue #102) added `hold_until()` with an explicit `abandoned` future
raced in a `select!`; when that arm wins, `hold_until` does `return
HoldOutcome::Abandoned`, which drops the *local* `guard` variable as normal
function-return cleanup — not because some external caller dropped a future.
This is the mechanism the PostgreSQL runtime actually uses (`HeldReader::watch_disconnect`
feeds the abandoned future). The two comments were not updated to mention this
second trigger, so they undersell/misdescribe how the guard is now invoked from
the mid-stream hold path.

**Why:** worth checking on any future change to `approval.rs`'s hold/guard
machinery — this file documents mechanism causality carefully, and adding a
new caller of a shared drop-guard is an easy way to make the guard's own doc
comment go stale without touching the doc's literal words at all (the words
are still true for the *old* caller, just incomplete for the new one).

**How to apply:** when reviewing changes to `approval.rs` or files that call
into `hold`/`hold_until`, re-check `CancelOnDrop`'s doc and the guard
construction comment against every current call path, not just the one being
edited.
