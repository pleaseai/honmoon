---
name: pr147-adr0007-flush-amended
description: ADR-0007's Flush bullet is amended in PR #147, as the convention requires — keep checking barrier PRs against it, but the #147 gap itself is closed
metadata:
  type: project
---

PR #112 (see [[honmoon_pg_runtime_timeout_docs]]) added the sync-point refusal-ordering barrier and,
in ADR-0007 Consequences, explicitly recorded a known residual gap: "A batch driven by `Flush` is
not ordered at all... A client using libpq pipeline mode can therefore still read a refusal ahead
of an earlier batch's responses, exactly as it did before this barrier." PR #112's own commit
history shows every mechanism change to this barrier was paired with a `docs(adr)` commit
amending ADR-0007 in the *same* PR — an established, repeated convention for this specific file.

PR #147 (issue #113) adds a second counter pair (`flushes`/`flush_answers`) that closes exactly
this gap — `await_forwarded_responses` now waits on both `sync_points` and `flush_answers`. An
early revision of that PR left ADR-0007 untouched, which is what this note was first written
about. **The PR then amended it, and the amendment is in the merged change** — the bullet now
reads "A batch driven by `Flush` is ordered against a quiet upstream, not against a marker" and
is kept rather than deleted ("this entry is amended rather than removed") precisely because the
new guarantee is weaker than the `Sync` one. It also records that a sync point settles the
flushes that preceded it, that one quiet settles one flush, that a written-off flush is owed back
as its own debt, and what remains unguaranteed. Do not flag ADR-0007 as stale for #113/#147.

**Why:** Found reviewing PR #147 for documentation drift. The convention the note establishes is
the durable part and it held: the repo's git history makes amending ADR-0007 in the *same* PR the
requirement for any change to this barrier, and #147 met it.

**How to apply:** When reviewing a PR that changes `postgres.rs`'s refusal-ordering barrier
(`ClientLink::forwarded`/`flushes`/`flushes_covered`/`delivered_message`/`await_forwarded_responses`/`relay_backend_messages`),
always diff the change against ADR-0007 Consequences, not just the file's own doc comments. If the
PR changes barrier behavior without a corresponding ADR-0007 amendment, flag both (a) the convention
violation and (b) the specific stale/contradicted prose. Verify against the ADR as it stands on the
PR head — this note's own first version flagged a gap the same PR had already closed.
