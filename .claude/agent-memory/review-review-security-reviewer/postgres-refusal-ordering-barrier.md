---
name: postgres-refusal-ordering-barrier
description: The honmoon postgres runtime's refusal ordering invariant (sync_points <= forwarded), what the barrier does and does not cover, and the one residual gap plus the settled rules not to undo.
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
them. The first two are live gaps; the rest are settled decisions that look like
bugs and must not be "fixed" back:
- `Flush` (`H`) produces no `ReadyForQuery`, so extended-protocol responses can
  be in flight with `delivered == forwarded` and a refusal can still overtake
  them (libpq pipeline mode).
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
