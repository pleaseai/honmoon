---
name: signed-body-detection-invariants
description: Invariants for crates/honmoon-proxy/src/signed_body.rs — over-inclusion is a redaction leak under --signed-body forward; current SigV4 rule after #81 narrowing
metadata:
  type: project
---

`signed_body.rs` decides whether a request's signature covers what wire redaction would rewrite
(body via `body_signature_scheme`, framing headers via `signed_headers_among`). `mitm.rs`
`forwarded_request` acts on it: under `--signed-body forward` *either* a "body-signed" or a
"framing-header-signed" classification forwards the ORIGINAL bytes, secret unredacted.

**Why:** over-inclusion is the leak direction (ADR 0006 states this explicitly); under-inclusion
only breaks the client's own signature (opaque upstream 403). So every predicate must require
genuine scheme evidence, not a single attacker-placeable token.

**Current SigV4 body rule (narrowed by #81, PR #120 — this replaces the older broad rule):**
1. `x-amz-content-sha256` declaring `UNSIGNED-PAYLOAD` / `STREAMING-UNSIGNED-PAYLOAD…` wins → not
   body-signed;
2. `Authorization: AWS4-HMAC-SHA256` / `AWS4-ECDSA-P256-SHA256` counts alone;
3. a presigned `X-Amz-Algorithm=AWS4-…` query parameter counts **only** with a
   `x-amz-content-sha256` that is a 64-char hex SHA-256 or `STREAMING-AWS4-…`;
4. a bare payload hash with no SigV4 authentication counts for nothing.

**How to apply:** when reviewing changes here, prove the new predicate is a *subset* of the old one
(any widening is a potential leak under `forward`), and keep the framing-header path gated:
`sigv4_signed_header_lists` only honours `X-Amz-SignedHeaders` when `aws_sigv4_authenticates`
(Authorization OR `sigv4_presigned_query`) holds — otherwise `?X-Amz-SignedHeaders=content-length`
is a bypass. Also check that the set the rewrite mutates (`REWRITTEN_FRAMING_HEADERS`,
`BODY_DIGEST_HEADERS`) is exactly the set detection asks about.

**Decision input vs. strip list (#116, PR #146):** `mitm::rewritten_headers` = `reframed_headers`
(framing headers the rewrite *would actually change*) + the `BODY_DIGEST_HEADERS` the request
*carries* (`headers.contains_key`). The strip loop removes every `BODY_DIGEST_HEADERS` name
unconditionally, but the decision must gate on carriage: refusing over a signature naming a header
the client never sent would be a `403` for a strip that removes nothing. Only SigV4 with
`UNSIGNED-PAYLOAD` reaches this branch over a digest — an RFC 9421 / cavage signature over a digest
header is body-signed and takes the earlier branch.

Known non-security gaps (compat, not leaks): `x-amz-content-sha256` is read via `header_str`, i.e.
only the first field value; and a payload hash carried as a *query* parameter on a presigned URL is
not considered, so such a body is redacted and the upstream rejects it.

Related: [[project-redaction-failopen-design]]
