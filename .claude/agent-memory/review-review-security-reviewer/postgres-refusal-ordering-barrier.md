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
(`watch::Sender<u64>`, bumped by the relay per `ReadyForQuery` actually written
to the client). `refuse()` waits `delivered >= forwarded` before taking the
writer lock, bounded by `REFUSAL_ORDER_TIMEOUT` (30 s).

**Why:** without it a refusal for a pipelined statement lands in front of the
previous statement's response, and the client attributes the 42501 to the wrong
query — in the worst reading, a *denied* statement looks like it succeeded.
Undercounting is the security-relevant direction; overcounting only delays.

**How to apply:** when this file changes, re-check these known residual gaps
rather than re-deriving them:
- `Flush` (`H`) produces no `ReadyForQuery`, so extended-protocol responses can
  be in flight with `delivered == forwarded` and a refusal can still overtake
  them (libpq pipeline mode).
- A `Sync` swallowed during `COPY` skews `forwarded` permanently ahead for the
  rest of the session, so *every* later refusal pays the full 30 s.
- The barrier shares the 5 s `ABANDONED_NOTICE_TIMEOUT` budget on the #102
  abandoned-hold path, and can consume it entirely.
- The barrier parks inside the `select!` in `run_postgres`, so a relay task that
  ends while it waits cancels the refusal outright.

Related: [[project-redaction-failopen-design]] — same fail-open-vs-fail-closed
weighting question, opposite answer (the proxy path is the enforcement backstop
and stays fail-closed).
