---
name: postgres-refusal-ordering-barrier
description: The honmoon postgres runtime's refusal ordering invariant (sync_points <= forwarded), what the barrier does and does not cover, its live gaps (the per-stall bound, the swallowed COPY-Sync of #128, and the two flush edge cases ADR-0007 records), and the settled rules not to undo.
metadata:
  type: project
---

`crates/honmoon-proxy/src/runtime/postgres.rs` orders a locally injected refusal
(`ErrorResponse` 42501 + `ReadyForQuery`) behind the responses the database still
owes: `ClientLink.forwarded` (AtomicU64, bumped per forwarded sync point —
startup handshake, `Q`, `Sync`, `FunctionCall`) vs `ClientLink.delivered`
(`watch::Sender<Delivered>`, bumped by the relay per backend message written to
the client, with the `ReadyForQuery` count and the write-off debt carried inside
it). `refuse()` waits for `sync_points >= forwarded` before taking the writer
lock, bounded by `REFUSAL_ORDER_STALL_TIMEOUT` (30 s) **per stall, not per
wait** — any delivered message restarts the window.

The load-bearing invariant is `sync_points <= forwarded`, held by construction:
`forwarded` only rises (a write-off credits `sync_points`, it never subtracts),
`sync_points` rises only under the clamp or a write-off's `max`, and every
mutation of the watched value goes through one `send_modify`. It is stated on
the `Delivered` type. Inverting it releases a refusal before the answer it was
ordered behind, which is #101 restored.

**Why:** without it a refusal for a pipelined statement lands in front of the
previous statement's response, and the client attributes the 42501 to the wrong
query — in the worst reading, a *denied* statement looks like it succeeded.
Undercounting is the security-relevant direction; overcounting only delays.

**How to apply:** when this file changes, re-read these rather than re-deriving
them. The `Flush` entry below is closed; the per-stall bound and the COPY-Sync of
#128 are live gaps, as are the two flush edge cases ADR-0007 records. The rest are
settled decisions that look like bugs and must not be "fixed" back:
- `Flush` (`H`) produces no `ReadyForQuery`. **Closed by #113/PR #147**: a second
  pair, `ClientLink::flushes` (raised when an `H` is forwarded) and
  `Delivered::flush_answers` (raised by the relay when the head's own `try_read`
  returns `WouldBlock` at a message boundary, guarded by `fresh > 0`, reset on
  `Z`, never armed after `D`/`d`), with the same `flush_answers <= flushes`
  invariant and the same stall write-off. Note the field: `delivered` is the
  whole watched value, and its `messages` count runs far ahead of `forwarded`;
  only `sync_points` (and now `flush_answers`) is the bounded one.

  **One quiet settles exactly one flush** — a settled decision that looks like an
  off-by-one and must not be "fixed" back. Crediting every outstanding flush was
  the first shape of the PR and three reviewers caught it: a client that flushes
  mid-batch (`Parse`/`Bind`/`Flush`/`Execute`/`Flush`, what `PQsendFlushRequest`
  is for) gets the first flush answered and then a quiet while the `Execute`
  computes, and crediting both there releases the refusal ahead of the rows —
  #101 through the #113 fix. Crediting one is wrong only when two batches
  coalesce into one burst, and that costs a stall window, not ordering. Pinned by
  `one_quiet_upstream_settles_one_flush_and_not_the_ones_behind_it`.

  **A written-off flush carries its own debt** (`Delivered::flush_debt`), separate
  from the sync `debt`. Codex caught the miss: after a write-off the client can
  send another flushed batch, and the *first* batch's late output then produces a
  quiet that is recomputed against the raised `flushes` and credited to the new
  batch — releasing a refusal while it is still computing, #101 by the same route
  the sync debt already guards. Recomputing the owed count from `flushes` is what
  makes the debt necessary, not what removes the need for it; the earlier doc
  comment argued the opposite and was wrong. Keep the two debts separate: crossing
  them lets a late `Z` discharge a flush's write-off or a quiet discharge a
  statement's. Pinned by
  `a_written_off_flush_is_not_settled_again_by_the_next_batch` and the tuple in
  `a_write_off_settles_both_counters_without_crossing_their_accounting`.

  Remaining, both recorded in ADR-0007 rather than open defects: a TCP-split
  burst can leave the socket empty part-way through one batch's output and settle
  it early (closing it needs a grace-period timing constant), and a `Flush` that
  elicits nothing is never settled, so a client can pay itself a fresh stall
  window per denied statement (#148).
- The 30 s bound is **per stall**, so any attacker-arranged continuous upstream
  stream (endless result set / `COPY TO`) resets it and holds a refusal
  indefinitely. Pre-existing for `sync_points`; the flush counter does not add a
  new unbounded path, but a lone `Flush` that elicits nothing costs one fresh
  window per denied statement rather than one per session (#148).
- A `Sync` swallowed during `COPY` is counted but can never be answered, and
  that now costs **every** later refusal on the connection a stall window, not
  just the first: the write-off records it as debt, and because no late answer
  for it ever arrives, the debt is paid down by the *next* statement's genuine
  `ReadyForQuery` instead, leaving the accounting one behind for good. Tracked
  as #128. Do not try to fix this by counting — the two cases are
  indistinguishable on the wire, and resolving the ambiguity the other way is
  exactly how a late answer gets credited to a later statement's slot. The error
  direction is safe (waits too long, never too little).
- **Settled in #112:** the barrier no longer consumes the whole 5 s
  `ABANDONED_NOTICE_TIMEOUT` budget on the #102 abandoned-hold path — ordering
  takes a 1 s slice and the write keeps the rest.
- **Settled in #112:** a relay task that ends while the barrier waits no longer
  cancels the refusal. The relay's exit releases the wait (`relay_finished`) and
  the `select!` in `run_postgres` is `biased` toward the message loop, so the
  `42501` is written before the session ends. Do not "fix" this back.
- **Settled in #112:** a relay that dies *mid-frame* suppresses the injection
  entirely (`relay_desynchronised` / `can_inject`), since the client would read
  the `ErrorResponse` as the missing payload. The flag is cleared by the relay
  **while it still holds the writer lock**, and checked under that lock — either
  half alone leaves a window.
- **Settled in #112:** a sync point is counted *before* the frame that earns it
  is forwarded. A fast database can be answered before the forwarding task runs
  its next line, and counting afterwards lets the clamp discard a genuine answer
  as an over-count.

Related: [[project-redaction-failopen-design]] — same fail-open-vs-fail-closed
weighting question, opposite answer (the proxy path is the enforcement backstop
and stays fail-closed).
