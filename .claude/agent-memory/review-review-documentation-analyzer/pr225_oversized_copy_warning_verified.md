---
name: pr225-oversized-copy-warning-verified
description: "PR #225 (issue #218) added a quiet-window warning inside the oversized-payload copy and amended ADR-0007 accordingly — every clause (does-not-poll/release/give-up, verbatim log line, four fields, once-per-copy, quiet-from-last-byte, bounded-copy rejection) verified true against postgres.rs and its own tests"
metadata:
  type: project
---

PR #225 closed issue #218 by adding `copy_exact_reporting_quiet` (crates/honmoon-proxy/src/runtime/postgres.rs), which races each read inside the oversized-backend-message streaming copy against `OVERSIZED_COPY_QUIET_WARNING` (== `REFUSAL_ORDER_STALL_TIMEOUT`, 30s) and logs once via `tracing::warn!` if a whole window passes with no byte from the database. ADR-0007's oversized-copy paragraph was expanded to describe this.

Verified accurate, clause by clause:
- "does not poll the injection channel, release anything or give up on anything" — true; the callback only calls `tracing::warn!`, no relay state is touched during the copy.
- The quoted log line matches the `tracing::warn!` message text exactly once Rust's `\` line-continuations are resolved.
- The four named fields (tag, payload_len, outstanding, holding_refusal) exist exactly as named; `outstanding` is the `len` argument the `FnOnce(usize)` callback receives from `copy_exact_reporting_quiet`, i.e., bytes still to be copied at the moment the deadline fires.
- "once per copy" — the callback is `Option<F>`, taken via `.take()` on first fire, so `until(stalled.is_some().then_some(deadline))` never re-arms; a test (`an_upstream_quiet_inside_an_oversized_payload_is_said_once_and_copied_whole`) pins this across two silence windows.
- "measured from the last byte read rather than from the start of the copy" — `deadline` resets after every successful read; a test (`a_payload_that_keeps_arriving_is_never_reported_as_quiet`) confirms zero reports across a copy that outlasts the window 3x via steady small reads. (Minor nuance: the very first window is unavoidably measured from copy-start since there is no prior read yet — not a defect, just an edge the prose doesn't spell out.)
- "the timer can do nothing but log" — confirmed; no write path in the function other than `dst.write_all` from the copy itself.
- Bounded-copy-rejected paragraph's "truncated payload / desynchronised stream" reasoning matches the code comment on the same partial-write scenario a few lines below.
- PR body (`gh pr view 225 --json body -q .body`) matches the final code on every count re-checked above; also correctly states `Relay::progressed`/`Relay::give_up` are unchanged.
- No other docs (`.please/docs/`, `AGENTS.md`, `crates/AGENTS.md`, `README.md`) reference the oversized-copy path, so nothing else needed updating.

Zero findings **from the documentation pass**, which is the only pass this note speaks for. The same review round did produce findings from other angles — the code pass caught the `deadline` re-arm sitting after the client write rather than after the read, which made this bullet's own wording imprecise and was reworded in-PR; read the merged prose rather than this note's paraphrase of it. The sibling issue #216 fixed a real gap in this exact area (see [[pr216_progressed_try_read_now_gap]]), so treat a clean docs pass here as calibration for the ADR text specifically, never as a verdict on the change.
