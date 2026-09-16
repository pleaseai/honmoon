---
name: postgres-refusal-ordering-barrier
description: 'The honmoon postgres runtime''s refusal ordering barrier after issue #121 (the relay owns the client write half) — what it covers, its live gaps (per-stall bound, the swallowed COPY-Sync of #128, the per-refusal window of #148, the single coverage snapshot of #153), the #211 inversion of the flush-settling tag list into a positive list, the #218 quiet warning inside the oversized copy (escaped tag, holding_refusal read at write time), the #229 second (client-side) window with its pinned non-recreated write_all, the #214 `last_tag` field on give_up''s stall warning (Option<u8>, unforgeable `none` sentinel) and the #248 `LoggedTag` wrapper that escapes a space or `=` tag byte at all three sites, and the settled rules not to undo.'
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
// since #210 (PR #252); see the #210 bullet at the end for the old spelling
self.sync.covers(refusal.sync_points) && self.flush.covers(refusal.flushes)
```

Each side's `received` is what the client really received; each side's
`abandoned` is a floor raised only when the relay gives up after
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
  reset on `Z`, and armed only after a tag that can end a batch
  (the positive list below). Crediting *every* outstanding flush was the first
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
- **The flush-settling tag check is a positive list, not an exclusion list** (#211,
  PR #212). `settling` now requires `last_tag` in `1 2 3 C I s E` — ParseComplete,
  BindComplete, CloseComplete, CommandComplete, EmptyQueryResponse,
  PortalSuspended, ErrorResponse. The old exclusion list (`D d N A S t T G H W c`)
  is gone; do not look for it and do not "restore" it. The new set is a strict
  subset of what the old one settled, so nothing settles that did not before.
  What actually changed behaviour is `n` (NoData) plus every byte nobody had
  enumerated — `V`, `K`, `R`, `v`, a future protocol tag, a non-protocol byte —
  which now wait. `T` and `t` are *not* part of that delta: they were already in
  the old exclusion list and already waited. `Z` is deliberately absent:
  `delivered` resets `fresh` on it and it settles through `flushes_covered`.
  The unenumerated default is now latency (one stall window), where it used to be
  ordering — that inversion is the load-bearing part, so adding a member is a
  safety decision and removing one is only a latency decision.
- **The cost of the inversion is one more batch shape reaching `give_up`.** A bare
  `Describe` plus a `Flush` is never settled by a quiet, so its refusal pays a full
  `REFUSAL_ORDER_STALL_TIMEOUT` unless a `Sync` answers for it. That was already
  true for the row-returning form ending on `T`; the inversion adds the no-row form
  ending on `n`. It is the #148 self-inflicted-stall shape widened by one shape, not
  a new one, and `give_up` stays fail-closed: it releases the refusal, never the
  statement.
- **`Relay::delivered`'s clamp bounds the total, not the position.** It stops a
  backend accumulating more sync-point credit than the session forwarded; it does
  not stop one that answers a single sync point twice from satisfying a refusal's
  tag one response early. That needs a protocol-violating upstream, which is not
  the adversary here — but do not read the clamp as per-statement robustness when
  hardening this file.
- **The stall window is re-armed by every *byte* off the upstream socket** (#209,
  PR #216). `Relay::progressed()` is called from every read that takes bytes off
  the upstream — the `Ok(read)` arm of `Relay::fill` and the settling
  `try_read_now` probe in `relay_backend_messages` — and from `Relay::delivered`
  once a message is whole. Since #210 the window is a field of
  `Pending::Waiting`, so it cannot be armed with nothing to release and
  `Relay::progressed` needs no guard — what that guard prevented was an
  empty-queue fire leaving `forced` latched, sending the *next* refusal
  unordered, and that combination no longer has a spelling. Do not
  re-report the old "a message trickling in is given up on mid-arrival" behaviour
  — it is gone. The indefinite-hold primitive is unchanged in class: a backend
  could always hold a refusal forever with one complete 5-byte message per window;
  #216 only lowers that to one byte per window and makes the hold invisible to the
  client. The **oversized-payload copy** (`copy_exact`, payload >
  `MAX_BUFFERED_BACKEND_MESSAGE`) still services neither the stall timer nor the
  injection channel, deliberately: the head is already on the client's socket, so
  an `ErrorResponse` written there would be eaten as that frame's payload. The
  copy ends in `delivered`, which re-arms in full. Since #218 the copy runs in
  `copy_exact_reporting_quiet`, which *does* poll one timer of the same length
  (`OVERSIZED_COPY_QUIET_WARNING == REFUSAL_ORDER_STALL_TIMEOUT`) — but its only
  effect is a single `tracing::warn!` per copy; it writes nothing, releases
  nothing and gives up on nothing, so the framing/ordering story above is
  unchanged. The copy is still exact (`want = len.min(buf.len())`, 16 KiB
  buffer filled before each write exactly as `copy_exact` does, `read == 0` ->
  `UnexpectedEof`), and the closure cannot write to the client because `dst`
  holds the mutable borrow. The line is the one place in this file a byte the
  database controls reaches a log record, and it reaches it **escaped**:
  `tag = %LoggedTag(tag)` since #248, `tag = %std::ascii::escape_default(tag)`
  before it. It was raw (`%(tag as char)`) in #225's first commit and was fixed
  in that PR after review — a raw newline there splits the record for any
  line-oriented collector (CWE-117). Do not re-report it, and do not cite the
  raw form as current.
  Its `holding_refusal` field is read **when the line is written**, not when the
  copy starts: `Relay::pending` (`Relay::queued` before #210) is snapshotted at
  the head because it cannot change during the copy, but the injection channel is
  read in the callback,
  because a statement refused part-way through waits there — a snapshot alone
  reported `false` for exactly the stalled-with-a-refusal session the field
  exists to name (also found and fixed in #225's review).

- **#229 added a second quiet window, on the client side of the same copy.**
  `copy_exact_reporting_quiet` now takes two `FnOnce` reporters (`upstream_quiet`,
  `client_quiet`), each `Option::take`n so each fires **at most once per copy**;
  both share the one `OVERSIZED_COPY_QUIET_WARNING`. The client window is armed
  per chunk and races a `tokio::pin!`ed `write_all` that is **resumed, never
  recreated** — recreating it would restart from the front of the 16 KiB buffer
  and duplicate bytes inside a frame whose length the client was already told.
  Verified once: the timer arm only calls the closure and loops back to the same
  pinned future, `until(None)` pends forever after the reporter is taken, the
  arms are `biased` toward the write, and both log lines escape the
  upstream-chosen tag (`std::ascii::escape_default`, wrapped in `LoggedTag`
  since #248) and carry only integers and a bool otherwise — no CWE-117 regression, no duplication/drop/reorder, no
  per-copy timer or allocation growth. Do not re-report these; the absence of a
  deadline on the copy remains deliberate (ADR-0007).


- **#214 put a third database-controlled byte in a log line: `give_up`'s
  `last_tag`.** `Relay::last_tag` became `Option<u8>` (`None` until a message is
  delivered) and the warning renders the tag escaped (through `LoggedTag` since
  #248), or the literal `"none"`. Settled once, do not re-derive:
  `std::ascii::escape_default` on ONE byte emits exactly one of — the byte
  itself for `0x20..=0x7e` except `\ ' "`, a two-char escape (`\t \r \n \\ \' \"`),
  or a four-char `\xNN`. So no newline/CR can ever reach the record (no CWE-117),
  and no output can spell `none` (that needs 4 chars with no backslash, and the
  only 4-char form starts with one) — the sentinel is unforgeable.
  **#248 closed the one residual that left.** `0x20` and `0x3d` used to pass
  through literally into an unquoted logfmt-ish field
  (`tracing_subscriber::fmt`, not JSON — see honmoon-cli main.rs), which could
  empty or mis-split a naive key=value read but could never forge a second field
  or a second record from one byte. All three tag fields now go through
  `LoggedTag`, a `Display` wrapper that renders those two bytes in the same
  `\xNN` form and defers to `escape_default` for every other byte, so a rendered
  tag is a bare logfmt token by construction. Do not re-report the residue, and
  do not propose taking one site back to bare `escape_default`: the three lines
  are meant to be read together and one answer for all of them was the point.
  The `u8` -> `Option<u8>` change does not touch fail-closed: the settling gate
  became `matches!(relay.last_tag, Some(b'1' | ...))`, and both the old `0`
  sentinel and the new `None` fail that match identically.
  The escaping has regression guards, so a later diff that drops it fails a test
  rather than needing this re-derived:
  `a_tag_that_would_split_the_record_is_escaped_into_it` drives a newline tag and
  asserts the warning stays one line carrying `last_tag=\n`;
  `a_tag_the_log_format_reads_as_structure_is_escaped_into_the_field` and
  `both_oversized_copy_lines_escape_a_tag_the_log_format_reads_as_structure`
  drive `0x20`/`0x3d` through give_up and through both copy lines; and
  `no_tag_byte_renders_as_something_an_unquoted_field_reads_as_structure` holds
  the rule over all 256 bytes.

- **#210 (PR #252) regrouped the barrier state into two types; behaviour is
  unchanged and was checked field-by-field, so do not re-derive the mapping.**
  `answered`/`abandoned` became `Relay::sync: Progress` and
  `drained`/`abandoned_flushes` became `Relay::flush: Progress`, with
  `Progress { received, abandoned }` private to a `mod progress` and
  `covers(tag) == received.max(abandoned) >= tag`. `releasable` is now
  `sync.covers(refusal.sync_points) && flush.covers(refusal.flushes)` — same
  sides, same tags. The settling gate in `relay_backend_messages` is
  `relay.flush.received() < owed`, i.e. delivered-only and deliberately **not**
  `covers()`; folding the write-off in there would stop the probe once a stall had
  written the flush off, so its own late output would never settle. Pinned by
  `a_written_off_flush_is_still_settled_by_its_own_late_output` — added in #252
  because nothing else in the suite could tell the two expressions apart.
  `flush_drained` -> `flush.receive_one(owed)` (clamped `+= 1`), `delivered`'s
  `drained.max(covered)` -> `flush.receive_through(covered)`, the `Z` arm ->
  `sync.receive_one(forwarded.sync_points)`, `give_up` -> `sync.abandon` /
  `flush.abandon`. `abandoned()` is `#[cfg(test)]` only.
  The `queued`/`forced`/`stall_deadline` triple became
  `Pending::{Empty, Waiting { injected, stall_deadline }, Forced(injected)}`.
  `write_queued` releases on `Forced(_) => true` and
  `Waiting => NoEncryption | releasable(refusal)` — identical to
  `forced || releasable`. `Pending::force()` on `Empty` is a no-op, which is the
  old latched-flag bug made unrepresentable; `Forced` is **transient** (the only
  builder is `write_unordered`, which is `force()` then `write_queued()` with no
  await between, and `write_queued` always takes a `Forced`), so `accepting()`,
  `progressed()`/`rearm()` (Waiting-only) and `stall_deadline()` (None on
  `Forced`) all behave as the old fields did. `dequeued_refusal` is
  `!relay.pending.is_empty()`, equal to the old `queued.is_some()` for every
  reachable state. The `#209` bullet above says `guarded on queued.is_some()`;
  read that as `Pending::rearm` now.

  Two things #252's own review got wrong at first, both worth not re-deriving.
  **`order_deadline()` is state-independent**, not `None` on `Forced`:
  `Pending::injected()` matches `Waiting { injected, .. } | Forced(injected)`, so
  the caller's ordering budget is read through whatever is queued and still fires
  on a `Forced`, exactly as the pre-#210 lookup ignored the `forced` flag. Only
  the *stall* bound stops applying, because that one is a field of `Waiting`.
  **The `mod progress` privacy does not make the crossing unwritable everywhere**
  — it makes it unwritable in the shipped binary, because reading a side's
  write-off at all is the `#[cfg(test)]` `abandoned()`. Under `cfg(test)`
  `self.sync.received().max(self.flush.abandoned())` compiles, since the
  assertions need both numbers. Claims stronger than that were written into the
  code comment and ADR-0007 on the first pass and corrected in review; do not
  restore them.
