---
name: pr147-adr0007-flush-gap-stale
description: PR #147 (issue #113) fixed the Flush-driven-batch ordering gap in postgres.rs but left ADR-0007's "A batch driven by Flush is not ordered at all" bullet unamended — a documented-convention violation
metadata:
  type: project
---

PR #112 (see [[honmoon_pg_runtime_timeout_docs]]) added the sync-point refusal-ordering barrier and,
in ADR-0007 Consequences, explicitly recorded a known residual gap: "A batch driven by `Flush` is
not ordered at all... A client using libpq pipeline mode can therefore still read a refusal ahead
of an earlier batch's responses, exactly as it did before this barrier." PR #112's own commit
history shows every mechanism change to this barrier was paired with a `docs(adr)` commit
amending ADR-0007 in the *same* PR — an established, repeated convention for this specific file.

PR #147 (issue #113, branch `amondnet/issue-113-flush-refusal-order`) adds a second counter pair
(`flushes`/`flush_answers`) that closes exactly this gap — `await_forwarded_responses` now waits on
both `sync_points` and `flush_answers`. But the diff touches only
`crates/honmoon-proxy/src/runtime/postgres.rs` (+367/-4); ADR-0007 is untouched, so its Consequences
section now states the opposite of what the code does.

**Why:** Found reviewing PR #147 for documentation drift. This is not a "missing ADR entry" style
gap (which would be out of scope) — it is an existing ADR paragraph now asserting something false,
which is squarely a doc/code contradiction (90-100 confidence tier), compounded by the fact that
the repo's own git history establishes updating ADR-0007 in-PR as the required convention for this
class of change.

**How to apply:** When reviewing a PR that changes `postgres.rs`'s refusal-ordering barrier
(`ClientLink::forwarded`/`flushes`/`delivered`/`await_forwarded_responses`/`relay_backend_messages`),
always diff the change against ADR-0007 Consequences, not just the file's own doc comments. If the
PR changes barrier behavior without a corresponding ADR-0007 amendment, flag both (a) the convention
violation and (b) the specific stale/contradicted prose.
