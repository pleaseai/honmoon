---
name: project-flush-refusal-barrier-pg113
description: PR #113 postgres.rs flush-answer barrier — sound design, one logging gap on write-off
metadata:
  type: project
---

PR #113 (`crates/honmoon-proxy/src/runtime/postgres.rs`) adds a second counter
(`ClientLink::flushes` / `Delivered::flush_answers`) so `await_forwarded_responses`
also waits for `Flush`-driven pipeline batches, settled by `upstream_has_pending`
(a `poll_peek`) observing the upstream socket quiet at a message boundary.

Verified sound: EOF and socket errors from `poll_peek` are deliberately treated as
"has pending" (never settle via the quiet path), but `relay_backend_messages`'
subsequent `read_exact` then fails and returns `RelayEnd::BetweenMessages`, which
calls `link.relay_finished()` — that sets `sync_points = None`, and the waiter's
`match` returns unconditionally on `None` regardless of `flush_answers`. So the
EOF/error path can never leave a refusal hanging. This is the same "deliberate skip
still needs its own logging/coverage" shape as [[feedback_framing_deliberate_skips]]
but here it checks out — no gap.

One real gap: the stall-window write-off in `await_forwarded_responses` (~line 550)
reuses the same `tracing::warn!` for both the sync and flush write-off, but only logs
`expected`/`delivered = seen` (sync-side fields). When the sync side is already
satisfied (`seen >= expected`) and only the flush side is unmet, the log reads as if
sync had already been satisfied and gives no hint that a `Flush` was the actual
unresolved cause — no `expected_flushes` / current `flush_answers` fields anywhere in
either warn (line ~507 also lacks them). Reported as a finding in the PR #147 review;
recheck if these warn! call sites are touched again.
