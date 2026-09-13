---
name: postgres-refusal-ordering-barrier
description: 'The honmoon postgres runtime''s refusal ordering barrier after issue #121 (the relay owns the client write half) — what it covers, its live gaps (per-stall bound, the swallowed COPY-Sync of #128, the per-refusal window of #148, the single coverage snapshot of #153), and the settled rules not to undo.'
metadata:
  type: project
---

`crates/honmoon-proxy/src/runtime/postgres.rs` orders a locally injected refusal
(`ErrorResponse` 42501 + `ReadyForQuery`) behind the responses the database still
owes. Since issue #121 there is **one writer of the client socket**: the
`upstream_to_client` relay owns the `OwnedWriteHalf`, and every answer honmoon
produces itself — a policy refusal, an uninspectable-frame refusal, the
abandoned-hold courtesy notice, and the single `N` that refuses encryption — is
handed to it over a one-slot `mpsc` as `Injected { what, written: oneshot }`. The
message loop awaits the ack; `Err(Unwritten)` is the only way it learns the answer
did not go out. There is no `Arc<Mutex<OwnedWriteHalf>>`, no `watch` channel, no
`Delivered` struct, no `debt`/`flush_debt`, no `can_inject`/`RelayEnd` — do not
search for them.

The barrier is now one predicate inside the relay:

```rust
self.answered.max(self.abandoned) >= refusal.sync_points
    && self.drained.max(self.abandoned_flushes) >= refusal.flushes
```

`answered`/`drained` are what the client really received; `abandoned`/
`abandoned_flushes` are floors raised only when the relay gives up after
`REFUSAL_ORDER_STALL_TIMEOUT` (30 s) with no backend traffic. The refusal's tags
are snapshotted from the single-writer message loop when the refusal is decided.
Shared state is three monotonic `AtomicU64`s (`Forwarded`) — see
[[honmoon-proxy-sync-point-tracking]].

**Why:** without the barrier, a refusal for a pipelined statement lands in front of
the previous statement's response and the client attributes the 42501 to the wrong
query — in the worst reading, a *denied* statement looks like it succeeded.
Undercounting the delivered side is the security-relevant direction; overcounting
only delays. Every ambiguity in this file is resolved toward waiting.

**How to apply:** when this file changes, re-read these rather than re-deriving
them. The live gaps are the per-stall bound, #128, #148 and #153. The rest are
settled decisions that look like bugs and must not be "fixed" back.

- **One quiet settles exactly one flush.** `Flush` (`H`) produces no
  `ReadyForQuery`; a flush is drained when the relay's own `try_read_now` of the
  next head returns `WouldBlock` at a message boundary, guarded by `fresh > 0`,
  reset on `Z`, and never armed after a tag that cannot end a batch
  (`D d N A S t T G H W c`). Crediting *every* outstanding flush was the first
  shape of PR #147 and three reviewers caught it: a client that flushes mid-batch
  (`Parse`/`Bind`/`Flush`/`Execute`/`Flush`, what `PQsendFlushRequest` is for)
  gets the first flush answered and then a quiet while the `Execute` computes, and
  crediting both there releases the refusal ahead of the rows. Pinned by
  `one_quiet_upstream_settles_one_flush_and_not_the_ones_behind_it`.
- **A sync point settles the flushes it covers, and the two sides never cross.**
  `flushes_covered` is snapshotted when the `Sync` is forwarded and applied when
  its `ReadyForQuery` is delivered. Crossing the two sides would let a late `Z`
  answer for a flush or a quiet answer for a statement. Pinned by
  `a_write_off_settles_both_counters_without_crossing_their_accounting` and
  `a_sync_point_that_covers_a_written_off_flush_settles_it`.
- **Give-up is a floor beside the delivered count, never a credit added to it.**
  This is what removed the pre-#121 `debt` bookkeeping. Do not "simplify" it by
  crediting the delivered count on give-up: that is exactly how an answer that
  arrives after all gets credited to a later statement's slot.
- **A sync point is counted *before* the frame that earns it is forwarded.** A
  fast database can be answered before the forwarding task runs its next line, and
  counting afterwards lets the relay's clamp discard a genuine answer as an
  over-count. Pinned by `an_answer_that_beats_the_forward_being_recorded_is_not_discarded`.
- **The relay checks the queue once more after a quiet settles a flush, before it
  blocks on the next read.** The read below it may never be satisfied. Dropping
  that call leaves the answer behind a wait nothing will end.
- **Suppression on a corrupted stream is ownership, not a flag.** A relay whose
  write failed mid-message drops the write half with itself
  (`upstream_to_client -> Option<HandBack>` returns `None`), so a queued answer
  dies with the channel and a later one finds it closed. On a clean message
  boundary the relay writes what it is holding and hands the writer back, and
  `run_postgres` writes any answer the loop decided afterwards with that half.
  The `select!` there stays **biased** toward the message loop so it can discover
  the channel closed rather than being dropped at random. Pinned by
  `a_relay_that_dies_mid_message_suppresses_the_refusal_rather_than_corrupting_it`
  and `the_relay_hands_its_writer_back_only_while_the_client_stream_is_framed`.
- **Rejected designs, recorded so they are not rediscovered.** (a) Suppressing the
  sync-point count for a `Sync` sent during copy-in: the message loop cannot know
  copy-in mode, and without a bound in the relay the forwarded count stays one
  ahead forever, the refusal is never released and the client hangs on a `42501`
  it never receives — worse than the out-of-order refusal #101 fixed. (b) Deriving
  flush coverage in the relay from the tag alone: unsound, see
  [[honmoon-proxy-sync-point-tracking]]. (c) A "lingering relay" that outlives the
  loop instead of handing the writer back: the upstream-ended signal lets
  `run_postgres` abort the relay while the loop is pending on its ack.

Live gaps:

- The 30 s bound is **per stall**, so any continuous upstream stream (endless
  result set, `COPY TO`) resets it and can hold a refusal indefinitely.
- A `Sync` swallowed during `COPY` is counted and can never be answered. The
  delivered count stays put while later statements raise the tag, so **every**
  later refusal on that connection pays a window, not just the first. Tracked as
  #128. Do not try to fix this by counting — the two cases are indistinguishable
  on the wire, and resolving the ambiguity the other way is how a late answer gets
  credited to a later statement's slot.
- A `Flush` that elicits nothing is never settled by a quiet, so a client can pay
  itself a fresh stall window per denied statement (#148). A TCP-split burst can
  also leave the socket empty part-way through one batch's output and settle it
  early; closing that needs a grace-period timing constant. Both recorded in
  ADR-0007 rather than open defects.
- `flushes_covered` is a single snapshot, so a second sync point overwrites the
  first's coverage (#153). Unchanged by #121.

Related: [[project-redaction-failopen-design]] — same fail-open-vs-fail-closed
weighting question, opposite answer (the proxy path is the enforcement backstop
and stays fail-closed).

Verified once against the #121 shape, so do not re-derive:

- **The barrier is airtight because the message loop is frozen while an answer is
  queued.** `ClientLink::inject` awaits the `oneshot` ack and the channel holds
  one slot, so between the `link.refusal(..)` snapshot and the relay's write
  nothing can be forwarded: `Forwarded` cannot move, `flushes_covered` cannot be
  overwritten, and `forwarded.sync_points == refusal.sync_points` for the whole
  wait. That is what makes `Relay::delivered`'s clamp sufficient (extra `Z`
  frames beyond the forwarded total are discarded) and what makes #153's stale
  coverage unexploitable. Any change that lets the loop forward while an
  injection is in flight — a channel deeper than one, or an un-awaited inject —
  breaks both at once.
- `order_deadline` is `Some` at exactly one construction site (the abandoned-hold
  courtesy notice in `decide`, which then returns `ClientGone`); `refuse` and
  `refuse_uninspectable` pass `None`. `Injection::NoEncryption` — the only
  unordered write in `write_queued` — is constructed only in `startup`, before any
  frame reaches the database.
- **`n` (NoData) is missing from the never-settle tag list** (`D d N A S t T G H W
  c`), while the list's own rationale names NoData as the alternative terminal of
  a `Describe`. A quiet after `NoData` in `Parse`/`Bind`/`Describe`/`Execute`/
  `Flush` settles that flush while the `Execute` is still computing. Unchanged
  from pre-#121, but a real asymmetry with `T` rather than a deliberate exclusion.
  Tracked as #211; the list is the third leak of the enumerate-from-the-wrong-side
  shape, so prefer inverting it to adding a twelfth byte.
- **`Relay::delivered`'s clamp bounds the total, not the position.** It stops a
  backend accumulating more sync-point credit than the session forwarded; it does
  not stop one that answers a single sync point twice from satisfying a refusal's
  tag one response early. That needs a protocol-violating upstream, which is not
  the adversary here — but do not read the clamp as per-statement robustness when
  hardening this file.
- **The stall window is re-armed by a *complete* message.** A single message whose
  bytes trickle in for longer than the window is given up on mid-arrival, so
  "waiting on N with no backend traffic" is really "with nothing whole delivered".
  Unchanged from pre-#121, tracked as #209.
