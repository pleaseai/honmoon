---
name: request-trailer-plumbing
description: 'Trailer handling in honmoon-proxy body.rs/mitm.rs after #82 — what bounds the trailer HeaderMap, which paths forward vs drop trailers, and what is (not) scanned'
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
- *Forbidden trailer names (#134, PR #175).* `body.rs::trailer_filtered_body` wraps the forwarded
  body in `inspect_body` (one call site, after all four `content_length` branches converge) and
  removes `FORBIDDEN_TRAILER_FIELDS`, plus whatever the request's own `Connection` header
  nominates (`connection_nominated`), from any trailer frame. **Read the list at HEAD, do not
  assume hyper's.** It is a deliberate *superset* of hyper's 12 `is_valid_trailer_field` names:
  the authentication category is completed (`cookie`, `proxy-authorization`, `www-authenticate`,
  `proxy-authenticate` added alongside `authorization`/`set-cookie`), h2's `CONNECTION_HEADERS`
  plus `connection` are included, and `Connection`-nominated names are resolved per request. The
  stated criterion is "could change how the recipient frames, routes, or authenticates the
  request"; the conditionals, `Range`, `Expect`, `Pragma` and `Accept*` are **deliberately
  excluded** with the reason recorded on the constant — do not file them as an omission without
  engaging that reason. Verified once, do not re-derive: hyper's h1 *decoder* (`decode_trailers`,
  `proto/h1/decode.rs:646`) filters no names on receive; the h2 client sends trailers via
  `send_trailers` (`proto/h2/mod.rs:223`) with no filter; and hyper's h1 *encoder* filter does
  **not** cover the connection-specific names, so this filter is load-bearing on both legs.
- *Framing.* `BufferedBody::size_hint` is exact over data bytes only; `is_end_stream` is false while
  trailers are pending, so hyper uses `write_body` + `write_trailers` instead of
  `write_body_and_end`. With a `Content-Length` (Kind::Length) encoder hyper silently drops the
  trailers (`can_write_body()` is already false); with chunked it honours only the fields listed in
  the request's `Trailer` header and filters `is_valid_trailer_field`. The h2 upstream leg applies
  NEITHER filter — `strip_connection_headers` runs on request headers only, not on trailers.
- *Redaction.* The wire-redaction rewrite still replaces the body with `Full`, deliberately dropping
  trailers (a stale digest is fail-safe), but it does not remove the now-meaningless `Trailer`
  request header alongside `BODY_DIGEST_HEADERS`.


**Framing headers honmoon writes itself (#136, PR #180).** `mitm.rs::framed_for_trailers` appends
`Transfer-Encoding: chunked` + `Trailer: <names>` to a pass-through request that carries a retained
trailer frame, and relies on hyper to reconcile the pair per leg. Verified once in hyper 1.10.1 /
h2 0.4.16 / hyper-util 0.1.20 / hudsucker 0.24.1 — do not re-derive:
- h1 `set_length` (`proto/h1/role.rs:1350-1428`) removes `Content-Length` only when
  `should_remove_con_len && existing_con_len.is_some()`, and `content_length_parse_all` returns
  `None` for *conflicting or unparseable duplicate* CL fields. So "the h1 leg drops the
  Content-Length" is true only when hyper parsed a length to drop — it was asserted
  unconditionally in README/ADR-0006/ADR-0009 and in the `framed_for_trailers` rustdoc, and for a
  CL hyper cannot resolve, TE:chunked would have shipped alongside two CL lines (a CL.TE
  primitive, CWE-444). **Closed in PR 180**: `content_length_is_unambiguous` declines the re-frame
  for any `Content-Length` that is repeated, comma-listed, non-digit or u64-overflowing, and all
  four documents now carry the proviso. Deliberately stricter than
  `content_length_parse_all` rather than a mirror of it. Pinned by
  `a_contradictory_content_length_declines_the_reframe` and
  `only_a_content_length_hyper_can_drop_is_unambiguous`. Do not re-flag; do re-check the guard
  still fronts the `Transfer-Encoding` append if `framed_for_trailers` is restructured.
- That input is reachable: h2 0.4.16 `recv_headers` reads CL with `fields().get()` (first value
  only) and never rejects a duplicate; hyper's h2 server keeps both fields; hudsucker
  `normalize_request` joins `Cookie` and forces `HTTP_11` but does not touch `Content-Length`.
  hyper's *h1* server does reject conflicting CL, so the vector is the h2 client leg only.
- h2 leg is fine: `strip_connection_headers` (`proto/h2/mod.rs:38-48`) removes `transfer-encoding`.
- `transfer_encoding_is_chunked`/`declares_trailer` in mitm.rs are exact mirrors of hyper's
  `headers::is_chunked` (`src/headers.rs:115-137` — *not* `proto/h1/headers.rs`, which does not
  exist; the doc comment said so and was corrected in PR 180) and of role.rs:1401-1418 — no
  parser differential there.
- `HeaderValue::from_str(join_names(...))` cannot panic or inject: `HeaderName::as_str` is
  lowercase token bytes only.

Related: [[signed-body-detection-invariants]], [[project-redaction-failopen-design]]
