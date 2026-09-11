---
name: project-signed-body-framing-headers-83
description: PR #115 (issue #83) extended ADR-0006's block/forward decision to signed framing headers; PR #146 (issue #116) closed the related digest-header gap — both reviewed clean
metadata:
  type: project
---

PR #115 added `signed_body::signed_headers_among`/`REWRITTEN_FRAMING_HEADERS` and
`mitm::reframed_headers` so a signature covering `Content-Length`/`Content-Encoding`/
`Transfer-Encoding` (the headers wire-redaction's body rewrite actually changes) takes the same
`--signed-body block|forward` decision as a body-signed request. Reviewed clean: compiles, clippy
`-D warnings` clean, all new tests pass, matches ADR-0006's updated text.

**Pre-existing gap noticed but correctly out of scope for that PR**: `forwarded_request` in
`crates/honmoon-proxy/src/mitm.rs` unconditionally strips `BODY_DIGEST_HEADERS` (`Digest`,
`Content-Digest`, `Content-MD5`, `Repr-Digest`) whenever it rewrites a body — this removal loop
predates #115 and #115 didn't touch it. `aws_sigv4_signs_body` only inspects
`x-amz-content-sha256`, not whether a SigV4 `SignedHeaders` list names `content-md5` (some S3
clients sign it for integrity). So a SigV4 upload with `UNSIGNED-PAYLOAD` that signs `content-md5`
in `SignedHeaders` would have that header silently stripped without tripping the block/forward
decision — an under-detection matching the [[feedback-trust-the-header-regression-pattern]] shape.
Not flaggable against #115 (code unchanged by that diff), but worth checking if a future PR
touches `sigv4_signs_header`/`REWRITTEN_FRAMING_HEADERS`/the `BODY_DIGEST_HEADERS` removal loop —
ask whether `BODY_DIGEST_HEADERS` should join the candidate list `signed_headers_among` is asked
about for SigV4 specifically.

**Resolved by PR #146 (issue #116, reviewed 2026-09-11).** Added
`mitm::rewritten_headers(headers, new_length)` = `reframed_headers(...)` plus the carried
`BODY_DIGEST_HEADERS`, fed into `signed_headers_among` at the same call site. Only headers the
request actually carries are included (avoids a spurious 403 for a `SignedHeaders` entry naming
an absent header). The `outcome.redacted` gate earlier in `forwarded_request` means this only
fires when a rewrite is actually happening, so no new false-positive 403 risk for untouched
requests. Reviewed clean: compiles, clippy `-D warnings` clean, new tests
(`carried_body_digest_headers_join_the_reframed_ones` in mitm.rs,
`unsigned_payload_upload_signing_content_md5_is_blocked_by_default` and
`a_signed_digest_header_the_request_never_sent_does_not_block` in redaction.rs) all pass. ADR-0006
updated in the same diff to fold this into the main decision-point prose and drop the now-resolved
Consequences bullet. No further gap in this area at this time.
