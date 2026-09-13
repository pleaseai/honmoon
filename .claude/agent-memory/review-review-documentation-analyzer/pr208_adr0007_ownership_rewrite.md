---
name: pr208-adr0007-ownership-rewrite
description: 'PR #208 (issue #121) rewrote ADR-0007''s ordering section for the relay-owned write half — verified clause-by-clause against postgres.rs; the four over-claims found (the lead bullet''s "goes through the relay", "only a pipeline that stops moving", the clamp''s reach, and NoData) were all corrected in that PR'
metadata:
  type: project
---

ADR-0007's "A local answer is injected in request order" section was rewritten in
PR #208 when the relay took sole ownership of the client write half. Verified
clause-by-clause against `crates/honmoon-proxy/src/runtime/postgres.rs`:
`Forwarded { sync_points, flushes, flushes_covered }`, the release predicate
`answered.max(abandoned) >= tag && drained.max(abandoned_flushes) >= tag`,
`Stop::{Upstream, Client}`, `upstream_to_client -> Option<HandBack>`, `TryRead`,
and `ABANDONED_NOTICE_TIMEOUT` (5 s) / `ABANDONED_NOTICE_ORDER_BUDGET` (1 s) all
match what the section says. `startup()`'s `SSL_REQUEST`/`GSSENC_REQUEST` arm does
call `link.inject(Injection::NoEncryption)` over the same one-slot `mpsc`, so the
"the single byte `N` goes the same way" claim holds.

## Four absolute claims that did not survive the check

All four were corrected in PR #208 before merge. They are recorded because each is
a different way for this section to over-reach, and the section will be amended
again:

1. **"every answer honmoon writes itself goes through it [the relay]"** — false for
   one path: `run_postgres`'s `ended.unwritten` fallback writes the
   `ErrorResponse`/`ReadyForQuery` directly with the handed-back `relayed.client`,
   from the message-loop task, after the relay has exited. The section's own later
   sub-bullet stated that case correctly, so only the topic sentence was wrong —
   which is where compression puts the over-claim.
2. **"Only a pipeline that stops moving expires"** — the stall window is re-armed by
   a **complete** message, so a single message whose bytes trickle in for longer
   than the window is given up on mid-arrival. A moving pipeline can expire. The
   behaviour is unchanged from before #121 and is tracked as #209.
3. **"the relay's clamp … so a backend cannot answer more sync points than it was
   asked for"** — the clamp bounds the session *total*, not the *position* of any
   one answer. A backend answering one sync point twice still advances the count.
4. **The exclusion list's rationale named `NoData` without excluding it** — `n` is
   `RowDescription`'s position for a statement returning no rows and is absent from
   the never-settle list, so the prose implied coverage the code did not provide.
   Tracked as #211.

**How to apply:** in this section, check the *topic sentence* of each bullet
separately from the sub-bullets under it — three of the four above were sentences
whose own section later stated the truth. Then grep the section for "only",
"never", "every", "cannot" and try to falsify each. Where the prose enumerates a
rationale (protocol tags, call sites), check the enumeration against the code's
list rather than against the rationale, because the two drift apart in exactly the
direction the rationale reads as covering.

Related: [[pr147_adr0007_flush_amended]] and
[[pr175_adr0006_untouched_forward_stale]] for the same absolute-claim pattern, and
[[docs-completeness-claim-unbounded-review]] for why narrowing a claim beats
qualifying it again.
