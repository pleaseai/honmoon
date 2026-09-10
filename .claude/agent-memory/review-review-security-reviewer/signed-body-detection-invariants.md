---
name: signed-body-detection-invariants
description: Invariants for crates/honmoon-proxy/src/signed_body.rs — over-inclusion is a redaction leak under --signed-body forward; each detector must be gated on real scheme evidence
metadata:
  type: project
---

`signed_body.rs` decides whether a request's signature covers what wire redaction would rewrite
(body via `body_signature_scheme`, framing headers via `signed_headers_among`). `mitm.rs`
`forwarded_request` acts on it: under `--signed-body forward` a "signed" classification forwards
the ORIGINAL bytes, secret unredacted.

**Why:** over-inclusion is the leak direction (ADR 0006 states this explicitly); under-inclusion
only breaks the client's own signature (opaque upstream 403). So every predicate must require
genuine scheme evidence, not a single attacker-placeable token.

**How to apply:** when reviewing changes here, check each detection source for its gate —
`Authorization` must pass `is_sigv4_authorization`, and a presigned `X-Amz-*` query parameter must
be accompanied by `X-Amz-Algorithm=AWS4-…` (`aws_sigv4_authenticates`). A detector that trusts a
bare query parameter turns "append `?X-Amz-SignedHeaders=content-length`" into a redaction bypass.
Also check that the set the rewrite mutates (`REWRITTEN_FRAMING_HEADERS`, `BODY_DIGEST_HEADERS`)
is exactly the set detection asks about — the module's stated one-definition rule.

Related: [[project-redaction-failopen-design]]
