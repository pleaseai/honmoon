---
name: project-trailer-contract-adr-133
description: PR #150 (ADR-0009, docs-only) reviewed clean against source; four-branch inspect_body trailer claims verified true, pre/post-#130 table verified against commit 023cf54
metadata:
  type: project
---

Issue #133 / PR #150 landed ADR-0009 declaring honmoon's request inspection covers **body bytes
only** — header and trailer values are never scanned for PII or secrets and never redacted, by
design. No behavior change; docs + pinning tests.

**Inspection is not forwarding — keep the two apart.** Whether a trailer *reaches* the upstream is
conditional: replayed on the pass-through path, but **dropped** when wire redaction rewrites the
body, because `forwarded_request` rebuilds it with `Full::new`, which carries no trailer frame
(`mitm.rs` ~L556-560 says so deliberately). The PR's first draft said "forwarded verbatim" and
three reviewers independently caught it. Also: `pii.count == 0` still *matches* on trailer-borne
secrets, because the engine binds `pii` with its empty default so absence conditions work — so a
`pii.count == 0 -> allow` rule allows such a request, and only *positive-finding* rules fail to
fire.

Verified against source (`crates/honmoon-proxy/src/mitm.rs::inspect_body`,
`crates/honmoon-proxy/src/body.rs::buffer_up_to`) and against `git show 023cf54`:
- All four `content_length` match branches in `inspect_body` forward trailers today; none scan
  them. Only the two buffered branches (`Some(len) <= MAX_INSPECT_BODY`, `None` within cap)
  materialize trailers via `buffered_body`; both over-cap branches leave the trailer frame unread
  in the passed-through stream.
- The ADR's pre-#130 table (branches 1/3 dropped trailers via `Full::new`, branches 2/4 already
  passed them through untouched) matches commit 023cf54's diff exactly.
- Nothing in the PII/secret scan path reads a `HeaderMap` — `pii_spans`/`detect_spans` derive only
  from `scanned`/`decoded` body bytes.
- New tests `trailer_content_is_outside_the_inspection_contract` and
  `the_same_content_in_the_body_is_refused_by_the_same_rule` both pass (`cargo test -p
  honmoon-proxy --test redaction`).
- No `decide()`/policy-struct/new-dependency changes — crates/AGENTS.md "ask first" list untouched.

One minor imprecision (not a defect, low-confidence flag only): the doc comment on
`buffer_up_to` in body.rs says "this branch is the only one that materializes trailers at all, so
a scan added here would cover the buffered paths" — literally, within `buffer_up_to`'s own two
arms that's true (Complete vs Overflow), but the Content-Length<=cap branch also materializes
trailers via a *different* code path (`body.collect()` in mitm.rs, not `buffer_up_to`), so "would
cover the buffered paths" (plural) overstates what widening the scan inside this one function
would actually reach. Worth a light copyedit if this doc comment is touched again, not worth
blocking on.
