---
name: pr208-relay-test-audit
description: 'PR #208 (issue #121) postgres.rs relay-owns-write-half refactor — every claimed test change audited and none weakened; the two guarantees its nine-case sabotage sweep missed (the injections_closed livelock latch and fill''s biased select) were found here and closed in the same PR'
metadata:
  type: project
---

PR #208 gave the upstream→client relay sole ownership of the client write half in
`crates/honmoon-proxy/src/runtime/postgres.rs`, replacing
`Arc<Mutex<OwnedWriteHalf>>` + `watch::Sender<Delivered>` with three `Forwarded`
counters, an `mpsc`/`oneshot` ack channel, and `struct Relay`.

## The claimed test changes, audited one by one — none weakened

1. **Deleted** `a_refusal_queued_at_the_writer_lock_sees_the_stream_break_under_it`.
   It pinned a mutex check-then-block TOCTOU that is now unreachable: only the relay
   task writes, so there is no second writer to race the framing check. Its
   behaviour is genuinely re-pinned by
   `a_relay_that_dies_mid_message_suppresses_the_refusal_rather_than_corrupting_it`,
   which queues the refusal over the channel *before* the stream breaks.
2. **Renames** (`..._clears_its_debt` → `..._settles_it`,
   `..._discharges_only_the_debt_it_proves` →
   `..._accounts_only_for_the_flushes_it_proves`) preserve the assertions exactly.
   They run through the new `Accounting`/`accounting()` harness, which calls the
   real `Relay::give_up`/`flush_drained`/`delivered` rather than reimplementing
   them — so there is no drift risk between harness and production path.
3. **One internal assertion dropped** (`flush_answers == 1` in
   `one_quiet_upstream_settles_one_flush_and_not_the_ones_behind_it`): `drained` is
   relay-task-local now and unreachable from that test's `Session` harness, and
   what replaced it — `still_waiting`/`written` on the `oneshot` ack — is a
   stronger end-to-end check of the same fact.
4. **The new tests** are all present and do what the PR body claims.

A full before/after diff of test `fn` names turned up no silently-weakened or
deleted test outside that list.

## The two gaps the sabotage sweep's nine cases missed

The PR verified its refactor by sabotaging each new mechanism and requiring a red
test. Nine cases, nine reds — but the sweep can only cover mechanisms someone
thought to sabotage, and these two were not on it. **Both were closed in PR #208
itself**, so they are recorded as the shape to look for rather than as open gaps:

- **`Relay::accepting()`'s `!self.injections_closed` latch prevents a livelock.**
  Once `run_postgres` drops the link, `injections.recv()` is `Ready(None)` on every
  poll forever, and that arm is *first* in `fill`'s `biased;` select — so without
  the latch it wins its own race indefinitely, the `read()` arm never runs again,
  and the relay spins instead of draining what the database still owes. Now pinned
  by `a_closed_injection_channel_does_not_stop_the_relay_delivering_what_is_still_owed`,
  which verified red (the 5 s timeout fires) with the latch removed.
- **`fill`'s `biased;` had no test that removing it would fail.** Every existing
  test sequenced its awaits so only one arm was ever genuinely ready per poll, so
  an unbiased random pick behaved identically. Now pinned by
  `a_refusal_already_decided_is_written_before_a_frame_already_on_the_socket`, which
  makes **both** arms synchronously ready in the same poll — the refusal already in
  the channel via `try_send`, the frame pre-buffered in `ScriptedUpstream.ready`
  rather than behind a sleep — and runs 32 rounds so an unbiased select cannot pass
  on a coin flip. It failed on round 1 with `biased;` removed.

**How to apply:** a sabotage sweep is evidence about the cases it lists, not about
coverage. When a PR offers one, read it as a checklist to extend: ask which
mechanisms in the diff are *absent* from it, and prefer the ones whose failure mode
is a hang or a spin, since those leave no assertion to go red on their own.

One candidate deliberately not pursued: `Relay::write_queued`'s
`Injection::NoEncryption => true` bypasses `releasable()`, and the real protocol
puts `SSLRequest` first, so the contended case is unreachable and a test for it
would pin a scenario the wire cannot produce.
