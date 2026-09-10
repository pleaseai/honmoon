---
name: postgres-refusal-ordering-barrier
description: The honmoon postgres runtime's refusal ordering invariant (forwarded vs delivered sync points), what the barrier does and does not cover, and the residual gaps to re-check on future edits.
metadata:
  type: project
---

`crates/honmoon-proxy/src/runtime/postgres.rs` orders a locally injected refusal
(`ErrorResponse` 42501 + `ReadyForQuery`) behind the responses the database still
owes: `ClientLink.forwarded` (AtomicU64, bumped per forwarded sync point —
startup handshake, `Q`, `Sync`, `FunctionCall`) vs `ClientLink.delivered`
(`watch::Sender<Delivered>`, bumped by the relay per backend message written,
with the `ReadyForQuery` count carried inside it
to the client). `refuse()` waits `delivered >= forwarded` before taking the
writer lock, bounded by `REFUSAL_ORDER_STALL_TIMEOUT` (30 s).

**Why:** without it a refusal for a pipelined statement lands in front of the
previous statement's response, and the client attributes the 42501 to the wrong
query — in the worst reading, a *denied* statement looks like it succeeded.
Undercounting is the security-relevant direction; overcounting only delays.

**How to apply:** when this file changes, re-check these known residual gaps
rather than re-deriving them:
- `Flush` (`H`) produces no `ReadyForQuery`, so extended-protocol responses can
  be in flight with `delivered == forwarded` and a refusal can still overtake
  them (libpq pipeline mode).
- A `Sync` swallowed during `COPY` still skews `forwarded` ahead, but only for
  one stall window: the wait writes the gap off, and a late answer to a
  written-off statement is discarded rather than credited.
- **Closed in #112:** the barrier no longer consumes the whole 5 s
  `ABANDONED_NOTICE_TIMEOUT` budget on the #102 abandoned-hold path — ordering
  takes a 1 s slice and the write keeps the rest.
- **Closed in #112:** a relay task that ends while the barrier waits no longer
  cancels the refusal. The relay's exit releases the wait (`relay_finished`) and
  the `select!` in `run_postgres` is `biased` toward the message loop, so the
  `42501` is written before the session ends. Do not "fix" this back.
- **Closed in #112:** a relay that dies *mid-frame* suppresses the injection
  entirely (`relay_desynchronised` / `can_inject`), since the client would read
  the `ErrorResponse` as the missing payload.

Related: [[project-redaction-failopen-design]] — same fail-open-vs-fail-closed
weighting question, opposite answer (the proxy path is the enforcement backstop
and stays fail-closed).
