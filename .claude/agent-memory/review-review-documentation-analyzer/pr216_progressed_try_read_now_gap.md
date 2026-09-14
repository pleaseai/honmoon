---
name: pr216-progressed-try-read-now-gap
description: 'PR #216 (issue #209) restored ADR-0007''s "every byte re-arms the window" claim and added Relay::progressed() called from delivered() and fill()''s read arm, naming the oversized-payload copy as the only exception — but relay_backend_messages'' `settling` branch reads the 5-byte header via TryRead::try_read_now (a raw non-blocking try_read, bypassing fill()) before calling fill(), so a header that arrives whole in one non-blocking read (or any zero-payload message completed there) never calls progressed(); a second, undocumented exception to the completeness claim'
metadata:
  type: project
---

ADR-0007 (`.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md`) and the
rustdoc for `Relay::progressed` in `crates/honmoon-proxy/src/runtime/postgres.rs` both
state, after PR #216, that a byte taken off the upstream wire always re-arms the stall
window, with **one** named exception (the oversized-payload streaming copy in
`relay_backend_messages`).

That completeness claim is one exception short. `relay_backend_messages`'s `settling`
branch (entered when `relay.fresh > 0` and the last tag was one of the
flush-terminating messages, used to detect a quiet upstream after a `Flush`) does a
direct non-blocking read via `TryRead::try_read_now(&mut head)` **before** calling
`Relay::fill`. `try_read_now` wraps `tokio::net::tcp::OwnedReadHalf::try_read`, which
can and does return a full 5-byte read in one syscall when the header is already
buffered. When that happens, `fill(..., filled = 5)` is called with `filled == buf.len()`,
so `fill`'s `while filled < buf.len()` loop body — the only place that calls
`self.progressed()` — never executes for those bytes. A message whose header (and, for
a zero-payload message like `NoData`, the whole message) arrives this way is real
backend traffic that does not re-arm the stall window, contradicting "every byte that
arrives from the database buys another window" and the progressed() rustdoc's "every
place a backend byte is taken off the wire — save the oversized-payload copy".

Practical impact is narrow (only fires mid-settling, right after fresh delivery already
re-armed the window recently, and needs a full header already buffered in the socket at
the moment of the non-blocking try), so this is a completeness/accuracy gap in the
documentation's "only one exception" claim rather than a functional security bug — but
it is the exact class [[pr208_adr0007_ownership_rewrite]] and
[[docs-completeness-claim-unbounded-review]] describe: an enumeration ("the one place")
drifts from the code's actual list.

**How to apply:** on any future edit to `Relay::progressed`'s call sites or to
`relay_backend_messages`'s settling branch, check `try_read_now` call sites specifically
— any raw read that bypasses `Relay::fill` is a candidate un-enumerated exception to
this completeness claim.
