---
name: pr236-client-quiet-second-window
description: "PR #236 (issue #229) added a second quiet-warning window for the client side of the oversized-payload copy; ADR-0007 and the PR body were verified accurate against copy_exact_reporting_quiet/postgres.rs line-by-line, zero findings — a second clean-PR calibration point in the same area as pr225"
metadata:
  type: project
---

PR #236 added `client_quiet` alongside the existing `upstream_quiet` in
`copy_exact_reporting_quiet` (crates/honmoon-proxy/src/runtime/postgres.rs), so a client that
stops draining mid-frame during the oversized-backend-message copy now gets its own
`tracing::warn!` line instead of producing no signal (the gap [[pr225_oversized_copy_warning_verified]]'s
window couldn't cover, since it only re-arms on database bytes and completed writes).

Verified accurate, clause by clause:
- Both quoted log lines in ADR-0007 match the two `tracing::warn!` message strings verbatim
  (mod Rust's `\` line-continuation joins).
- Both closures carry exactly `tag`, `payload_len`, `outstanding`, `holding_refusal` — same four
  fields, same escaping (`std::ascii::escape_default`) on `tag`.
- `outstanding` differs by design and the ADR states it correctly: the upstream closure receives
  `len - filled` (what `src` still owes mid-read), the client closure receives `len` (what `dst`
  has not yet taken, chunk-in-flight included, captured before `len -= want`).
- The client `client_deadline` is armed right before `dst.write_all` is pinned (per chunk) and
  raced against the resumed `write_all` future with `biased` select — matches "armed per chunk,
  answered when the write completes."
- "One constant on purpose" — `OVERSIZED_COPY_QUIET_WARNING` is the sole timeout for both races;
  no second constant was introduced anywhere in the diff.
- "Each reported once per copy, counted separately" — `client_quiet`/`upstream_quiet` are each
  `Option<F>` taken via `.take()` on first fire; four tests pin the client side the same way
  pr225's tests pinned the upstream side: two against a scripted `AsyncWrite` double
  (`a_client_that_stops_taking_the_payload_is_said_once_and_the_copy_completes`,
  `a_client_that_keeps_taking_the_payload_is_never_reported_as_stopped`), one over a real
  loopback socket with shrunken kernel buffers asserting the relay's own line at the call site
  (`a_client_that_stops_draining_an_oversized_payload_is_said_at_the_call_site`), and one with
  both ends stalled in a single copy (`a_copy_stuck_on_both_ends_says_so_once_about_each`).
- PR body's "write-side re-arm of the upstream window is untouched" — confirmed: the
  `deadline = Instant::now() + quiet` line after the write completes is unchanged context in the
  diff, not a `+`/`-` line.
- PR body's mutation table (four rows) matches the tests and their asserted failure modes
  exactly (client timer never fires -> client_quiet 0 vs 1; write_all recreated -> a byte sent
  twice; client window armed once per copy -> client_quiet 1 vs 0; loopback buffers left at
  their default -> no client line because the payload fit in the kernel).
- No stray ADR sentence still speaks of "one window" as the only one — the whole oversized-copy
  paragraph (.please/docs/decisions/0007..., roughly lines 150-240) was consistently rewritten to
  "two windows"/"two of them"/"each"; the unrelated Flush-ordering section further down (lines
  ~303-393) uses "quiet upstream" in a different mechanism and was untouched by this diff, so it
  is not a stale reference to flag.

Zero findings. Second calibration point after [[pr225_oversized_copy_warning_verified]] in the
same oversized-copy area — both PRs kept the ADR, the function doc comment, and the PR body in
sync with the code on the first pass.
