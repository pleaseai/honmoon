---
name: pr180-trailer-reframe-signed-subset
description: "honmoon-proxy signed_headers_among call sites pass a computed subset, not the named constant — docs that say a signature over any of the framing headers declines are wrong; corrected for the trailer re-frame in PR 180, check the phrasing on any new one"
metadata:
  type: feedback
---

`crates/honmoon-proxy/src/mitm.rs::framed_for_trailers` builds a `reframed: Vec<HeaderName>`
holding only the headers it is about to change — `Content-Length` only if present and `!chunked`,
`Transfer-Encoding` only if `!chunked`, `Trailer` only if a retained trailer is undeclared — and
calls `signed_headers_among(headers, uri, &reframed)`, **not** `&TRAILER_FRAMING_HEADERS`.
Concretely: on an already-chunked request with an under-declared `Trailer`, `reframed == [TRAILER]`,
so a signature covering `Content-Length` does *not* decline the re-frame.

**Status: the docs were corrected in PR 180.** README.md, ADR-0006 and ADR-0009 had all stated the
check as unconditional over the fixed three-header constant; each now carries the "that this
re-frame would actually touch" qualifier, matching the phrasing the sibling
`REWRITTEN_FRAMING_HEADERS` rustdoc already used ("exactly the members that rewrite would change").
Do not re-flag those three documents for this.

**Why:** the project already had correct phrasing for the analogous body-rewrite mechanism, so the
omission was an inconsistency with its own established wording rather than an ambiguity in the
code. Per [[docs-completeness-claim-unbounded-review]], "a signature over any of them" is an
unbounded claim that a narrower implementation quietly falsifies.

**How to apply:** on any doc describing `signed_headers_among` or framing-header decline logic,
open the call site and check whether it passes the full named constant or a computed subset. If a
subset, the prose needs the "only the ones that would actually change" qualifier.
