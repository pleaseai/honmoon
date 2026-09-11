---
name: socks-fake-pg-upstream-swallows-sync
description: crates/honmoon-proxy/tests/socks.rs's start_pg_upstream fake PostgreSQL server answers Q, P and Sync but still drops FunctionCall/Bind/Execute/CopyData — FunctionCall is the one remaining sync point it drops, a latent 30s-timeout trap for ordering-barrier integration tests
metadata:
  type: project
---

`crates/honmoon-proxy/tests/socks.rs`'s `start_pg_upstream()` fake database
loop (around line 78-111) only replies to `b'Q'` (simple query) and `b'P'`
(Parse, with a bare `ParseComplete`). Every other frontend tag — `Sync`,
`Bind`, `Execute`, `FunctionCall`, `CopyData` — falls into `_ => continue`:
the byte are read off the socket but nothing is written back, so the fake
upstream never emits a `ReadyForQuery` for a `Sync`.

**Why it matters**: `crates/honmoon-proxy/src/runtime/postgres.rs` (added in
PR #112, the pipelined-refusal-ordering barrier) counts `Sync` and
`FunctionCall` as sync points a locally injected refusal must wait behind
(`ClientLink::forwarded_sync_point`, `await_forwarded_responses`, bounded by
`REFUSAL_ORDER_STALL_TIMEOUT` = 30s). Any future `tests/socks.rs` integration test
that pipelines the extended protocol (Parse/Bind/Execute/Sync) ahead of a
refused statement will silently eat the full 30s timeout per test run,
because this fake upstream never answers the `Sync`. It's a latent trap, not
a bug in production code — the fake upstream needs a `b'S' => ReadyForQuery`
(and ideally `b'F'`) reply added before it can be used to write an
integration-level test of the ordering barrier.

**How to apply**: when reviewing tests that exercise the extended protocol
(or the sync-point ordering barrier) against this harness, check whether
`start_pg_upstream` was updated to answer `Sync`/`FunctionCall`; if not, flag
either the missing upstream-fidelity fix or the absence of an integration-level
ordering test as a gap. See [[mitm-test-harness]] for a similar fake-upstream
fidelity gap in the MITM test harness (different subsystem, same pattern:
Honmoon's test doubles trading realism for hermeticity in ways that can hide
regressions in newly-added protocol logic).

**Update (PR #112):** `start_pg_upstream` now answers `Sync` with
`ReadyForQuery`, so the trap below is closed for `Sync` itself. What remains
un-replied is `FunctionCall` (`F`), `Bind`, `Execute` and `CopyData` — of which
only `FunctionCall` is a sync point honmoon counts, so keep the caution scoped
to that one rather than to `Sync`.
