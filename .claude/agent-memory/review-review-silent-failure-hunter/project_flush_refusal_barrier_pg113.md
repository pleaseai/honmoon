---
name: project-flush-refusal-barrier-pg113
description: 'PR #113/#147 postgres.rs flush-answer barrier — the EOF-as-pending path was safe via relay_finished, and issue #121 replaced that mechanism entirely; what to check on the EOF path now, and which warn fields survived'
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

## Rewritten by issue #121 — the safety argument moved, the guarantee did not

`RelayEnd`, `relay_finished`, `sync_points = None`, `await_forwarded_responses`
and its two `tracing::warn!` sites are all gone. Do not search for them.

The EOF/error-from-`try_read` path is still the one to check, and it is still
safe, but for a different reason. The probe is now `upstream.try_read_now(&mut head)`
in `relay_backend_messages` (the receiver is that function's `upstream` parameter,
not the `Relay`), and `Ok(0)` / `Err(_)` return `Stop::Upstream`
without settling the flush — exactly as before. What changed is what makes that
harmless: `upstream_to_client` handles `Stop::Upstream` by setting
`relay.forced = true` and writing whatever answer it is holding before it returns
the write half. So a refusal outstanding at EOF is **written**, not released into a
wait that nothing ends, and it cannot be silently dropped. The clean-exit and
corrupt-exit paths are distinguished by whether a `HandBack` is returned at all,
so there is no flag whose staleness could swallow the answer.

The write-off warning survived as `Relay::give_up`, which logs one
`tracing::warn!` naming both sides and both floors. Check those fields are still
there if that function is touched: a give-up that logs nothing is the silent
failure this note was originally about.
