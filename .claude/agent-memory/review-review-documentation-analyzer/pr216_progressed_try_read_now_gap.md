---
name: pr216-progressed-try-read-now-gap
description: 'PR #216 (issue #209) restored ADR-0007''s "every byte re-arms the stall window" claim and first named the oversized-payload copy as its only exception — review found a second one, relay_backend_messages'' settling branch reading the header through a raw try_read_now that bypasses Relay::fill; closed in the same PR by covering the probe, so the single-exception claim is now true. The reusable check: on any claim of this shape, enumerate the raw read sites, not the ones the abstraction names.'
metadata:
  type: project
---

ADR-0007 (`.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md`) and the
rustdoc for `Relay::progressed` in `crates/honmoon-proxy/src/runtime/postgres.rs` state
that a byte read off the upstream always re-arms the stall window, with **one** named
exception: the oversized-payload streaming copy in `relay_backend_messages`.

As first written in PR #216 that enumeration was one short, and the miss is the
instructive part. `relay_backend_messages`'s `settling` branch — entered when
`relay.fresh > 0` and the last tag was one of the flush-terminating messages, to probe
for the quiet that settles a `Flush` — reads the head through
`TryRead::try_read_now(&mut head)` **before** calling `Relay::fill`. `try_read_now` is a
raw non-blocking read (`OwnedReadHalf::try_read` in production, mirrored in the test
harness's `ScriptedUpstream`), and when it returns the whole 5-byte header `fill` is
entered with `filled == buf.len()`, so `fill`'s `while filled < buf.len()` body — which
carries the only `progressed()` call in that function — never runs for those bytes.

**Closed in #216 itself**, by calling `relay.progressed()` from the probe's `Ok(read)`
arm. So do **not** report the settling probe as an un-enumerated exception on a later
review: the code covers it and the single-exception claim is accurate against the merged
head. It was covered rather than documented as a second exception even though it cannot
change an outcome on its own — the probe does not await, so it runs in the same instant
as the `delivered` that ended the previous loop iteration, and that call has just
re-armed. Covering it keeps the rule at one stated exception instead of two, and stops a
later `await` inserted above the probe from reintroducing #209 in that corner unnoticed.

**How to apply:** this is the enumeration-drift class [[pr208_adr0007_ownership_rewrite]]
and [[docs-completeness-claim-unbounded-review]] describe, with a specific tell. When a
claim quantifies over an *operation* ("every read", "every write", "every message"),
resolve the list from the raw call sites — `grep` the trait method or syscall — not from
the helper the prose names. A read that bypasses `Relay::fill` is invisible to anyone
enumerating `fill`'s call sites, which is how three finders and the author all had to
reach the same conclusion the hard way.
