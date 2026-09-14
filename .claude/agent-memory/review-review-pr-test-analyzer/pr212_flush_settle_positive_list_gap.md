---
name: pr212-flush-settle-positive-list-gap
description: "How to test the postgres flush-settling tag list, and why a test that looks like it pins the flush barrier may be held by the sync-point half instead: isolate the flush side with forwarded_flush + queue_refusal and no forwarded_sync_point, and check written()'s 10s window against the 30s stall timeout before believing a settle assertion."
metadata:
  type: project
---

The flush half of the refusal barrier (`crates/honmoon-proxy/src/runtime/postgres.rs`)
is easy to test vacuously. Two checks before believing any test of it:

**Isolate the flush side.** `Relay::releasable` requires *both*
`answered >= refusal.sync_points` and `drained >= refusal.flushes`. A test that calls
`link.forwarded_sync_point()` leaves the refusal held by the sync-point clause, so it
passes whatever the flush logic does. Call `queue_refusal` straight after
`forwarded_flush()` and nothing else — then `refusal.sync_points == 0`, that clause is
trivially satisfied, and the assertion really is about the flush. Every template test in
the module does it this way.

**Check the assertion window against the stall timeout.** A test asserting a refusal
*is* released (`written`) can pass through `Relay::give_up` rather than through
settling. `written` waits 10s and `REFUSAL_ORDER_STALL_TIMEOUT` is 30s, so today the
give-up path cannot satisfy it — but that is a numeric coincidence between two
constants, so re-check it if either moves.

**The positive list is fully covered as of PR 212.** The list
(`1 2 3 C I s E`) is a positive claim about which tags can end a flushed batch, so it
needs coverage on both halves, and it now has it:

- negative half — `a_no_data_before_the_completion_does_not_settle_the_flush` and
  `a_tag_the_settling_list_does_not_name_settles_nothing`. Both were confirmed to fail
  against the pre-inversion exclusion list before the fix landed.
- positive half — `every_tag_the_settling_list_names_does_settle_a_flush` drives `3`,
  `I`, `s` and `E` each as the settling trigger; `1`, `2` and `C` are driven by the
  batch tests elsewhere in the module. Confirmed non-vacuous by dropping `b's'` from the
  list and watching it fail.

So do **not** report "the positive list members are untested" on a later PR without
re-grepping first. One protocol note, because it looks like a defect and is not:
`s` `PortalSuspended` belongs in the list. A suspended portal does still have rows, but
fetching them needs another `Execute` from the client, so the backend has stopped and
that flush's own output is complete — unlike `D` `DataRow`, where it has not.

See also [pr208-relay-test-audit] for the general audit method (trace every claim to a
measured behaviour, and verify a revert fails by hand rather than reading the diff).
