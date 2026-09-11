---
name: request-trailer-plumbing
description: Trailer handling in honmoon-proxy body.rs/mitm.rs after #82 — what bounds the trailer HeaderMap, which paths forward vs drop trailers, and what is (not) scanned
metadata:
  type: project
---

Since PR #130 (issue #82) the buffered request paths in `mitm.rs::inspect_body` rebuild the body
with `body.rs::buffered_body(bytes, trailers)` instead of `Full`, so a client's trailer frame
(e.g. an RFC 9421 `Content-Digest` a signature covers) survives the PII scan and reaches upstream.

**Why:** `Full` carries no trailers, so `--signed-body forward` forwarded a request the client
never signed and the upstream rejected the signature.

**How to apply** when reviewing trailer-touching changes:
- *Memory bound.* Trailers are NOT counted against `MAX_INSPECT_BODY` (2 MiB). They are bounded
  upstream instead: hyper h1 `TRAILER_LIMIT` = 16 KiB (or `http1_max_headers`/`max_header_size` if
  set) and h2 `DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE` = 16 KiB, and both protocols emit at most one
  trailer frame per stream, so the `HeaderMap::extend` merge cannot accumulate. Re-verify these two
  hyper defaults before accepting any change that buffers more header-ish data.
- *Inspection scope.* `detect_spans`/`detect_secrets` see body bytes only — request headers AND
  trailers are never scanned or redacted. Trailer content is therefore an unscanned egress channel,
  but only at parity with request headers, which were already unscanned. **ADR-0009 (#133, accepted
  2026-09-11) makes this the stated contract**: bodies only, header-shaped fields out of scope,
  silent (no warn about their contents, `pii.count` stays 0, and no audit *attributable to a
  positive finding* — an absence rule `pii.count == 0 -> deny`/`pause` does match a trailer-only
  secret and does record its verdict; only a clean `allow` stays unaudited), pinned by
  `trailer_content_is_outside_the_inspection_contract` in `tests/redaction.rs`. Treat a future
  "scan the trailers" change as a deliberate contract change, not a bug fix. Two caveats the ADR
  states more strongly than the code supports: redacting a trailer is only blocked for *signed*
  requests (the existing `--signed-body` forward/block gate already decides that class), and a
  `Trailer:` *declaration header* is readable on all four `content_length` branches, so a
  warn-on-trailers signal would not be confined to the buffered paths (an adversary can just omit
  the declaration, which is the real reason it is weak).
- *Framing.* `BufferedBody::size_hint` is exact over data bytes only; `is_end_stream` is false while
  trailers are pending, so hyper uses `write_body` + `write_trailers` instead of
  `write_body_and_end`. With a `Content-Length` (Kind::Length) encoder hyper silently drops the
  trailers (`can_write_body()` is already false); with chunked it honours only the fields listed in
  the request's `Trailer` header and filters `is_valid_trailer_field`. The h2 upstream leg applies
  NEITHER filter — `strip_connection_headers` runs on request headers only, not on trailers.
- *Redaction.* The wire-redaction rewrite still replaces the body with `Full`, deliberately dropping
  trailers (a stale digest is fail-safe), but it does not remove the now-meaningless `Trailer`
  request header alongside `BODY_DIGEST_HEADERS`.

Related: [[signed-body-detection-invariants]], [[project-redaction-failopen-design]]
