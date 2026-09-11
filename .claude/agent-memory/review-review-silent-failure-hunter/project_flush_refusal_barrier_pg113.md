---
name: project-flush-refusal-barrier-pg113
description: 'PR #113 postgres.rs flush-answer barrier — sound design (the EOF/error-as-pending peek is safe via relay_finished); the write-off logging gap it found was fixed in-PR'
metadata:
  type: project
---

PR #113 (`crates/honmoon-proxy/src/runtime/postgres.rs`) adds a second counter
(`ClientLink::flushes` / `Delivered::flush_answers`) so `await_forwarded_responses`
also waits for `Flush`-driven pipeline batches, settled by the relay reading the
message head with `upstream.try_read` and finding the socket empty at a message
boundary (`WouldBlock` calls `flush_drained`). An earlier revision used a
`poll_peek` helper named `upstream_has_pending`; both are gone — do not search
for them.

Verified sound: EOF and socket errors from that `try_read` return
`RelayEnd::BetweenMessages` rather than settling the flush, which
calls `link.relay_finished()` — that sets `sync_points = None`, and the waiter's
`match` returns unconditionally on `None` regardless of `flush_answers`. So the
EOF/error path can never leave a refusal hanging. This is the same "deliberate skip
still needs its own logging/coverage" shape as [[feedback_framing_deliberate_skips]]
but here it checks out — no gap.

The one gap found — both `tracing::warn!` sites in `await_forwarded_responses`
logging only the sync-side `expected`/`delivered = seen`, so a stall caused by an
unmet `Flush` read as though nothing was outstanding — **was fixed in PR #147
itself**. Both now carry `expected_flushes`, and the stall-window one also logs
`drained`. Do not re-report it; check the fields are still there if these call
sites are touched again.
