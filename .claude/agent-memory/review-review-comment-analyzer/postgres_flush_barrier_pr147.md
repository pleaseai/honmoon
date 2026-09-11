---
name: postgres-flush-barrier-pr147
description: PR #147 (issue #113) flush-driven-batch barrier comments in crates/honmoon-proxy/src/runtime/postgres.rs
metadata:
  type: project
---

PR #147 added `ClientLink::flushes`/`forwarded_flush`, `Delivered::flush_answers`/
`flush_drained`, and relay-local `credited`/`fresh`/`last_tag` bookkeeping to close
issue #113 (a `Flush`-only pipelining client wasn't ordered against by the #112
sync-point barrier). Every specific technical claim in the new doc comments was
verified accurate by hand-tracing the code and the four new tests:
- `flush_answers <= flushes` holds by the same construction as
  `sync_points <= forwarded` (monotonic counter + values only ever read before
  being used to raise the derived field).
- The writer-lock race justification for not settling on "first delivered
  message" is real: `link.writer` (a tokio Mutex) is re-acquired per message in
  `relay_backend_messages`, not held across a burst.
- The `D`/`d` (DataRow/CopyData)-exclusion claim matches the real PG v3 protocol:
  Execute results terminate in CommandComplete/EmptyQueryResponse/
  PortalSuspended/ErrorResponse; copy-out terminates in CopyDone.
- `upstream_has_pending`'s EOF-reports-Ready claim is correct and harmless: the
  `None`-relay-finished short-circuit in `await_forwarded_responses` ignores
  `flush_answers` entirely once the relay has ended.

Only issue found: the pre-existing `Delivered` `# Invariant` doc block still
enumerates only the `sync_points <= forwarded` invariant and doesn't
cross-reference the new analogous `flush_answers <= flushes` one (which is
documented, correctly, only on the `flush_answers` field itself). Not factually
wrong, just an incomplete first-read entry point. Low confidence/severity.

**Why:** this file's dense load-bearing comment style (see
[[postgres_sync_point_protocol_claims]]) means PRs touching it tend to be
comment-heavy and worth the line-by-line trace; PR #147 is the second such PR
and came back essentially clean.
**How to apply:** if a third counter pair is ever added to this barrier
(mirroring `forwarded`/`flushes`), check whether the `# Invariant` block has
been updated to at least point at the per-field docs for the newer pairs.
