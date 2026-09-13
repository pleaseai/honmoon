---
name: paused-clock-real-socket-hazard
description: 'A tokio start_paused test that awaits a real socket can have auto-advance jump the clock by tens of seconds mid-await (28.672 s observed on loopback), so any assertion about *when* a timeout fired needs a scripted in-memory peer instead — the failure looks like an off-by-30s bug in the code under test'
metadata:
  type: reference
---

`#[tokio::test(start_paused = true)]` auto-advances the clock whenever the runtime
has nothing to poll but a timer. If the test also awaits a **real socket**, the
runtime can reach that state while socket readiness is still in flight, jump to the
next timer deadline, and charge the wait for time that never elapsed on the wire.

Measured in `crates/honmoon-proxy/src/runtime/postgres.rs` (issue #121): a plain
`database.write_all(&[b'G', …])` on a loopback pair consumed **28.672 s** of paused
time — 7 × 4096 ms, a tokio timer-wheel slot boundary, not a value from the code
under test. The late delivery then re-armed a 30 s stall window, so
`Instant::now() - started` came back as 59.952 s against an asserted 30 s.

**The tell:** an elapsed-time assertion that misses by ~a whole timeout, or by a
clean multiple of 4096 ms, on a test that both pauses the clock and touches a
socket. Read it as a harness artefact before reading it as a bug in the timer being
tested.

**How to apply.** Do not flag such a test as under-specified and do not "fix" it by
widening the assertion to a range — that deletes the guarantee. Drive the timing
test through an in-memory peer so nothing in the wait path needs socket readiness:
this file's `ScriptedUpstream` is the pattern (an `AsyncRead` + `TryRead` over a
`VecDeque<(Duration, Vec<u8>)>` script, an empty chunk meaning EOF), and the test
then calls the relay loop directly and asserts an exact deadline. Keep real sockets
for the ordering and framing tests, which assert *what* was written and in what
order rather than *when*.

Related: [[socks_fake_pg_upstream_swallows_sync]] for the other direction — a fake
peer that is too simple to exercise the path under test.
