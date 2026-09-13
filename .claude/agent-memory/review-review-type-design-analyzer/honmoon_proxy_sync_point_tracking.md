---
name: honmoon-proxy-sync-point-tracking
description: 'The three shared counters in crates/honmoon-proxy/src/runtime/postgres.rs (Forwarded) after issue #121 — why Relaxed is correct, why the give-up floors are deliberately NOT in shared state, and the encapsulation gap that survived the rewrite'
metadata:
  type: project
---

`crates/honmoon-proxy/src/runtime/postgres.rs` orders a locally injected refusal
behind the responses the database still owes. Since issue #121 the shared state
between the two tasks is exactly one struct:

```rust
struct Forwarded {
    sync_points: AtomicU64,
    flushes: AtomicU64,
    flushes_covered: AtomicU64,
}
```

**Written only by the message loop, read only by the relay, and only ever
raised.** Everything else the barrier needs — how many answers the relay has
really delivered, how far a stalled wait has given up, the relay's freshness
count and last tag — is relay-task-local, not shared, and is not reachable from
the message loop at all. The refusal itself carries its tag (`Refusal { message,
sync_points, flushes, order_deadline }`) down a one-slot `mpsc`, so the value
the refusal is measured against is snapshotted at the decision rather than
re-read later.

**Why `Relaxed` is correct, and what the argument actually rests on.** `Relaxed`
gives atomicity and per-location modification order, not a happens-before edge,
so the relay may read a stale value. Because every field only rises, a stale read
is always *low*, and low reads only ever make the relay wait longer: the clamp
(`if self.answered < forwarded.sync_points`) declines an increment, and the
coverage (`self.drained.max(flushes_covered)`) applies less credit. Declining
costs a stall; allowing costs the ordering guarantee. **If a future edit makes any
of these three non-monotonic, this argument is gone** — not because of data
visibility (nothing is published *through* them; no pointer or payload's
visibility depends on them), but because a stale read could then err high.
Anyone reaching for `Acquire`/`Release` "to be safe" should know that is what
they would be replacing.

Do not lean on the practical reinforcement that two syscalls, the wire and the
database's turnaround sit between the increment and the read. It is true today
and it is an argument from the environment, not from the memory model: the
`ScriptedUpstream` test harness in this file already short-circuits the loopback.

**The give-up floors are deliberately not here.** `Relay::abandoned` /
`abandoned_flushes` live in the relay task because giving up is the relay's own
decision, taken from its own read deadline. The predicate is
`answered.max(abandoned) >= tag && drained.max(abandoned_flushes) >= tag`, which
is why the pre-#121 `debt` / `flush_debt` bookkeeping is gone rather than
reimplemented: a late answer raises the truthful count, the floor is unmoved by
it, and neither number has reached a later statement's tag. Putting a floor back
into shared state would recreate the "credit then remember the credit" shape the
rewrite removed.

**Why `flushes_covered` has to be shared, though it looks like it could be
derived.** It is the flush count as it stood when a sync point was forwarded, and
the relay applies it when that sync point's `ReadyForQuery` is *delivered* —
which can happen before any refusal exists, so it cannot ride on the refusal.
Deriving it in the relay from the tag alone is unsound: with `Flush`1,
`Sync`(covering 1), `Flush`2, a relay that took `max(drained, coverage)` from the
tag would conflate two different flushes. It is still only one snapshot, so a
second sync point overwrites the first's coverage — the reason issue #153 is
neither fixed nor worsened by #121.

**Known gap, unchanged by the rewrite (reported, moderate confidence, not
critical)**: the fields are module-private, not struct-private via a submodule,
so any code in `postgres.rs` — the tests included — can bypass the
`forwarded_sync_point` / `forwarded_flush` / `refusal` method surface and touch
them directly. A real fix (nested submodule, or an explicit read accessor for
tests) was judged plausible but not clearly required: the file is cohesive and
each call site is comment-justified. Useful context if more call sites for
counter tracking appear here later.

Related: [[postgres-refusal-ordering-barrier]] for what the barrier does and does
not cover, and the live gaps.
