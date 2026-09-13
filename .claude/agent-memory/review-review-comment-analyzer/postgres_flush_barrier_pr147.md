---
name: postgres-flush-barrier-pr147
description: 'PR #147 (issue #113) flush-driven-batch barrier comments in crates/honmoon-proxy/src/runtime/postgres.rs — the flush counters verified accurate end-to-end, and which of those claims issue #121 then deleted; the D/d protocol-exclusion claim is the part that survives'
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

Only issue found, and fixed in PR #147 itself: the pre-existing `Delivered`
`# Invariant` doc block enumerated only the `sync_points <= forwarded`
invariant and did not cross-reference the analogous `flush_answers <= flushes`
one (which was documented, correctly, only on the `flush_answers` field). Never
factually wrong, just an incomplete first-read entry point. The merged block now
names the second pair explicitly and points at its per-field docs — do not
re-report it.

**Why:** this file's dense load-bearing comment style (see
[[postgres_sync_point_protocol_claims]]) means PRs touching it tend to be
comment-heavy and worth the line-by-line trace; PR #147 is the second such PR
and came back essentially clean.
**How to apply:** if a third counter pair is ever added to this barrier
(mirroring `forwarded`/`flushes`), check whether the `# Invariant` block has
been extended to point at the per-field docs for it, the way PR #147 extended it
for `flush_answers`.

## Amended by issue #121 — two of these claims no longer have code

The barrier still counts flushes, but the types named above are gone. Do not look
for `Delivered`, `flush_answers`, `flush_drained` as a `Delivered` method, the
`# Invariant` doc block, or `await_forwarded_responses`.

- **Dead: the writer-lock race justification.** `link.writer` (the tokio `Mutex`)
  no longer exists — the relay owns the `OwnedWriteHalf` outright, so the "why not
  settle on the first delivered message" argument now has to be made from the
  relay's own `try_read_now` probe, not from lock re-acquisition. A comment still
  making the lock argument is stale prose, not a live claim.
- **Dead: the `flush_answers <= flushes` invariant as a stated pair.** Bounding is
  now `drained.max(abandoned_flushes) >= refusal.flushes` inside the relay, and
  `drained` is relay-task-local rather than shared, so there is no shared value to
  state an invariant *on*. The monotonicity argument moved to the three
  `Forwarded` counters — see [[honmoon-proxy-sync-point-tracking]].
- **Alive and re-verified at #121: the `D`/`d` exclusion.** The list widened to
  `D d N A S t T G H W c` and the protocol reasoning is unchanged (an `Execute`
  ends on `CommandComplete`/`EmptyQueryResponse`/`PortalSuspended`/`ErrorResponse`,
  a copy-out on `CopyDone`). The comment still enumerates what *cannot* end a
  batch rather than what does — see [[enumerate-from-the-wrong-side]] for why that
  shape keeps leaking.

**How to apply (revised):** the "was a third counter pair added, and was the
`# Invariant` block extended" check is obsolete. The live equivalent is: if a
counter is added, is it monotonic, is it read only by the relay, and is the
stale-read-errs-low argument still stated where the field is declared.
