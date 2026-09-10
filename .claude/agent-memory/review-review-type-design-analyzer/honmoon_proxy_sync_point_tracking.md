---
name: honmoon-proxy-sync-point-tracking
description: ClientLink's forwarded/delivered sync-point counters in crates/honmoon-proxy/src/runtime/postgres.rs — how the refusal-ordering barrier is built and its known encapsulation gap
metadata:
  type: project
---

`ClientLink` (crates/honmoon-proxy/src/runtime/postgres.rs) carries a
`forwarded: Arc<AtomicU64>` / `delivered: Arc<watch::Sender<u64>>` pair that
implements the barrier ordering an injected refusal behind the database's
answers to statements already pipelined ahead of it (issue #101, PR #112).

**Why the asymmetry is correct, not an inconsistency**: `forwarded` is
written and read only from the single task running `client_to_upstream`
(never spawned — awaited directly in `run_postgres`'s `tokio::select!`), so
`Ordering::Relaxed` is safe purely from same-task program order, no
cross-thread synchronization needed. `delivered` is written by the spawned
`upstream_to_client` task and read (waited on) by the `client_to_upstream`
task — that cross-task edge is supplied by `tokio::sync::watch`'s internal
synchronization, not by atomic ordering. A plain `AtomicU64` for `delivered`
would need `Acquire`/`Release`, not `Relaxed`; `watch` was chosen precisely
to get correct synchronization *and* wakeup-without-polling in one type.

**Known gap (reported, moderate confidence, not critical)**: the invariant
`delivered <= forwarded` and "bump at exactly the right call sites" is
enforced only by convention/comments across ~5 call sites in one file, not
structurally. Because the fields are module-private (not struct-private via
a submodule), any code within `postgres.rs` — including the test at the
line reading `link.forwarded.load(...)` directly — can bypass the
`forwarded_sync_point`/`delivered_sync_point`/`await_forwarded_responses`
method surface. A real fix (nested submodule for true privacy, or an
explicit read accessor for tests) was judged plausible but not clearly
required — the file is cohesive/single-purpose and each call site is
carefully comment-justified, so YAGNI cuts against forcing extraction. Useful
context if this file grows more call sites for sync-point tracking later.
