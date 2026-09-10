---
name: approval-hold-abandonment-model
description: How a paused (pause verdict) hold is cancelled when the client disconnects, and the documented MAX_HELD_PIPELINE escape hatch that reopens issue #102
metadata:
  type: project
---

`hold_until` in `crates/honmoon-proxy/src/approval.rs` takes an `abandoned` future and races it
against the decision channel in a **biased** `select!` (decision arm first). The PostgreSQL runtime
(`crates/honmoon-proxy/src/runtime/postgres.rs`) feeds it `HeldReader::watch_disconnect()`, which
reads the client socket during the hold and buffers anything pipelined behind the held statement.

**Why:** a `pause` on the PG path is held mid-stream inside a `select!` whose upstream-relay arm
stays healthy, so the `CancelOnDrop` guard alone never sees a disconnect (GitHub issue #102 — a
human could approve a statement for a client that had already left).

**How to apply:** two known soft spots to check on any future change here —
1. `watch_disconnect` stops watching (`std::future::pending()`) once `MAX_HELD_PIPELINE`
   (= `MAX_PG_FRAME`, 1 MiB) is buffered. Past that cap the pre-fix #102 behaviour returns: a
   departed client's statement can still be approved and forwarded. Documented in ADR-0007 as a
   deliberate anti-buffering trade-off, not an oversight — but it is a fail-open direction.
2. The abandoned path audits `Decision::Rejected` via the drop guard; there is no distinct audit
   decision for "client left", so log consumers cannot tell abandonment from a human rejection.

Related: [[project-redaction-failopen-design]] (the project's other documented fail-open).
