---
name: honmoon-proxy-sync-point-tracking
description: ClientLink's forwarded/delivered sync-point counters in crates/honmoon-proxy/src/runtime/postgres.rs — how the refusal-ordering barrier is built, why Relaxed is still correct now that both tasks read `forwarded`, and its encapsulation gap
metadata:
  type: project
---

`ClientLink` (crates/honmoon-proxy/src/runtime/postgres.rs) carries a
`forwarded: Arc<AtomicU64>` / `delivered: Arc<watch::Sender<Delivered>>` pair that
implements the barrier ordering an injected refusal behind the database's
answers to statements already pipelined ahead of it (issue #101, PR #112).

**Why the asymmetry is correct, not an inconsistency**: `delivered` is written
by the spawned `upstream_to_client` task and read (waited on) by the
`client_to_upstream` task — that cross-task edge is supplied by
`tokio::sync::watch`'s internal synchronization, not by atomic ordering. A plain
`AtomicU64` there would need `Acquire`/`Release`, not `Relaxed`; `watch` was
chosen precisely to get correct synchronization *and* wakeup-without-polling in
one type.

**`forwarded` is `Relaxed` for a different reason, and the old one no longer
holds.** It used to be written *and* read only from `client_to_upstream`, so
same-task program order was the whole argument. That stopped being true when
`delivered_message` began reading it (inside its `send_modify`) to clamp the
sync-point count — the relay's task reads it now. `Relaxed` is still correct, but the
reasons are not co-equal and it matters which one you are relying on.

**The load-bearing reason: `forwarded` only ever rises.** `Relaxed` gives
atomicity and per-location modification order, not a happens-before edge, so the
relay may read a stale value. Because the counter is monotonic, a stale read is
always *low*, and a low read makes the clamp `*count < forwarded` **decline** an
increment where it might otherwise allow one. Declining costs a stall; allowing
costs the ordering guarantee. That is the same safe-direction argument as the
rest of the design, and it stands on its own.

**A supporting reason: nothing is published *through* it.** It carries no
pointer or payload whose visibility another thread depends on, so no
acquire/release edge is needed to transfer data. Note what this does and does
not establish — it says an edge is unnecessary, not that the relay sees the
latest value. On its own it is not enough.

**A practical reinforcement that is not part of the argument:** between the
increment and the relay's read sit two syscalls, the wire, and the database's
own turnaround, which supply synchronisation far stronger than the atomic would.
True today, but an argument from the environment rather than from the memory
model — a refactor that moves the increment, or a test harness that
short-circuits the loopback, removes it without touching this line. Do not lean
on it.

So: if a future edit makes `forwarded` non-monotonic, the real argument is gone
and `Relaxed` must be revisited — not because of data visibility, but because a
stale read would then be able to err high. Anyone reaching for `Acquire`/`Release`
"to be safe" should know that is what they would be replacing.

**Known gap (reported, moderate confidence, not critical)**: the invariant is
now *stated* — a `# Invariant` section on `Delivered` names it as
`sync_points <= forwarded` and lists the three things that keep it — but it is
still only *enforced* by convention across the call sites in one file, not
structurally. Because the fields are module-private (not struct-private via
a submodule), any code within `postgres.rs` — including the test at the
line reading `link.forwarded.load(...)` directly — can bypass the
`forwarded_sync_point`/`delivered_message`/`await_forwarded_responses`
method surface. A real fix (nested submodule for true privacy, or an
explicit read accessor for tests) was judged plausible but not clearly
required — the file is cohesive/single-purpose and each call site is
carefully comment-justified, so YAGNI cuts against forcing extraction. Useful
context if this file grows more call sites for sync-point tracking later.
