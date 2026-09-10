---
name: postgres-held-reader-cursor-races
description: honmoon-proxy postgres runtime tests using std::io::Cursor as the client reader cannot create genuine async races with a concurrently-spawned approver task — relevant when reviewing HeldReader/hold_until tie-break tests
metadata:
  type: project
---

`crates/honmoon-proxy/src/runtime/postgres.rs`'s `HeldReader<R>::watch_disconnect` and
`crate::approval::hold_until`'s biased `select!` are meant to prove that an approval decision
already in hand beats a simultaneous client disconnect (issue #102).

Tokio's `impl AsyncRead for std::io::Cursor<T>` (`tokio-*/src/io/async_read.rs`) is **always
`Poll::Ready` synchronously** — reading past the end returns `Ok(0)` immediately, never
`Pending`. A test that builds its "client" as `HeldReader::new(std::io::Cursor::new(...))` and
also spawns a `tokio::task::spawn` "approver" loop racing to resolve the approval therefore cannot
exercise a real race: on a `#[tokio::test]` (default current-thread runtime), the disconnect
branch resolves inside the very first poll of `hold_until`'s `select!`, before the executor ever
gets a chance to run the separately-spawned approver task (no `Pending` ever bubbles up to yield
control). The approver task is polled zero times and its `.abort()` afterward is a no-op on an
already-orphaned task.

Concretely this affects
`a_client_that_leaves_mid_hold_cancels_its_approval_and_forwards_nothing` in
`crates/honmoon-proxy/src/runtime/postgres.rs`: it correctly proves "already-disconnected client
never gets a forwarded statement," but its docstring/comment framing ("exactly the race the defect
allowed") overclaims — it does not exercise the biased-tie-break logic. That logic *is* genuinely
exercised in `crates/honmoon-proxy/src/approval.rs`'s
`a_decision_already_in_hand_beats_a_simultaneous_abandonment`, which uses a real `tokio::sync::Notify`
(no synchronous-Ready future) so both `select!` arms become ready only after the spawned resolver
task actually runs — that one is a true tie-break test.

**How to apply**: when reviewing a postgres-runtime test that claims to test a race/tie between an
approval and a disconnect, check what the "client" is backed by. `std::io::Cursor` (or any other
`AsyncRead` impl that never returns `Pending`) makes the disconnect win unconditionally regardless
of scheduling — not a real race. A real loopback `TcpStream` (as in
`crates/honmoon-proxy/tests/socks.rs`) or a `Notify`-driven future is required for a genuine
interleaving test.
