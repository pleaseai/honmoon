# ADR-0006: Body-signed requests under wire redaction

## Status

Accepted

## Context

`--redact-secrets` rewrites intercepted request bodies: detected secrets and Tier-1 PII are
replaced with deterministic placeholders before the upstream leg, and the placeholders are
restored on the response. The rewrite changes the body bytes and their length, so
`forwarded_request` already strips the validators that describe the old bytes (`Content-MD5`,
`Digest`, `Content-Digest`, `Repr-Digest`) and re-frames `Content-Length`. The upstream recomputes
those, so nothing breaks.

A **signature** is different. When a request's authentication covers the payload — AWS Signature
Version 4 binds `x-amz-content-sha256`, RFC 9421 HTTP Message Signatures can cover a
`content-digest` component, draft-cavage `Signature` can cover a `digest` header — the signature
is computed by the client with credentials honmoon does not hold. Stripping the digest header does
not help: the signature itself is over the old bytes. The review of #56 flagged that the code knew
this and did nothing about it; `forwarded_request` carried a comment ("Honmoon cannot re-sign
authenticated body bytes") and then forwarded the rewritten body anyway. The upstream rejects it
with `SignatureDoesNotMatch` or an equivalent, which surfaces to the agent as an unexplained
failure at the far end of a TLS-terminated tunnel — one of the hardest failure shapes to diagnose.

The tempting fix, "fail open whenever an `Authorization` header is present", is wrong and
dangerous. Bearer tokens, Basic auth, and API-key headers authenticate the *caller*, not the
bytes; a request carrying one can be rewritten freely. Since almost all agent traffic to model
providers and SaaS APIs is bearer-token authenticated, that rule would silently disable wire
redaction for nearly all of it — turning a narrow compatibility problem into a blanket secret
leak. The same applies to a bare `Digest`/`Content-Digest`/`Content-MD5` with no signature: it is
a stale validator, already handled by stripping it.

The payload is only half of what redaction changes. Rewriting a body also re-frames the headers
that *describe* it — `Content-Length` has to match the new bytes, and the replacement is decoded
UTF-8 text rather than the client's compressed or chunked representation, so `Content-Encoding` and
`Transfer-Encoding` are dropped. SigV4 signs *headers* even when it does not sign the payload, and
an AWS SDK upload routinely lists `content-length` in `SignedHeaders`. The review of #80 found
that the `UNSIGNED-PAYLOAD` exception below therefore only means the body is not signature-bound:
those uploads still broke on the signature, which is the outcome this decision exists to prevent
(#83). The Decision covers both halves.

Re-signing is the other direction one could take: give the gateway the client's AWS credentials
and have it produce a fresh SigV4 signature over the redacted body. That turns the gateway into a
credential holder for every signed upstream an agent talks to, which is a larger blast radius than
the problem being solved and contradicts the design premise that honmoon sees traffic but not
long-lived secrets.

## Decision

**Detect only schemes whose signature actually covers the body**, in
`honmoon-proxy::signed_body::body_signature_scheme`:

- **AWS SigV4** — an `Authorization` starting with `AWS4-HMAC-SHA256` or `AWS4-ECDSA-P256-SHA256`
  (SigV4A), a presigned `X-Amz-Algorithm=AWS4-…` query parameter, or — as a deliberately
  conservative fallback — a bare hex `x-amz-content-sha256` payload hash. That header is an
  integrity check, not itself a signature, but a hash of the exact body bytes is inseparable from
  whatever signed those bytes, so treating it as body-binding errs toward fail-closed rather than
  risking a silent signature mismatch. **Exception:** `x-amz-content-sha256: UNSIGNED-PAYLOAD` or
  `STREAMING-UNSIGNED-PAYLOAD…` declares the body explicitly out of the signature, so those stay
  redactable.
- **RFC 9421 message signatures** — a `Signature` header alongside `Signature-Input` (RFC 9421
  requires both; either may repeat across field values, all of which are scanned) whose component
  list names a body-digest header, under a label `Signature` actually carries. Labels are matched
  because both fields are dictionaries keyed the same way: a member naming a digest says nothing
  about a *different* member that is the one actually signed. A component's own `;param="…"` value
  is not a covered component, so `"@query-param";name="content-digest"` does not count.
- **draft-cavage** — a `Signature` header, or an `Authorization: Signature …` value, whose
  `headers="…"` parameter (tolerating whitespace around `=`) names a body-digest header.

The body-digest set is the same for both schemes and is **the set of validators the rewrite path
strips** — `digest`, `content-digest`, `content-md5`, `repr-digest`. Signing any of them binds the
body: the digest cannot survive a rewrite, and stripping it as a stale validator breaks the
signature outright. Detection and stripping therefore read one constant,
`signed_body::BODY_DIGEST_HEADERS`, rather than two lists kept aligned by convention — a header
stripped but not detected is exactly the opaque upstream rejection this ADR exists to prevent, and
that divergence should not be reachable by editing one file.

Everything else — bearer tokens, Basic auth, API keys, bare digest headers — is not body-signed
and keeps being redacted.

**A signature over a framing header the rewrite changes takes the same decision.**
`signed_body::signed_headers_among` parses the actually-covered list — a SigV4 `SignedHeaders`
list (from the `Authorization` credential or a presigned `X-Amz-SignedHeaders` query parameter,
whose `;` separators are percent-encoded), an RFC 9421 component list under a label `Signature`
carries, or a draft-cavage `headers="…"` parameter — and asks it about
`signed_body::REWRITTEN_FRAMING_HEADERS` (`content-length`, `content-encoding`,
`transfer-encoding`). That constant is read by both the rewrite and the detection, for the reason
`BODY_DIGEST_HEADERS` is. Only a header the rewrite would *actually* change counts: a
`Content-Encoding` the request never sent, or a `Content-Length` the redacted body happens to
match, is left as the client signed it and does not block anything. A request that trips this
takes the same `--signed-body` decision as a body-signed one, under its own
`X-Honmoon-Reason: signed-header-redaction`, audit rule `wire-redaction/signed-headers`, and a
message naming the headers rather than the scheme.

Two coarser rules were rejected. Treating *any* header-signing authentication as body-signed would
refuse the entire `UNSIGNED-PAYLOAD` upload path — the case the exception exists for — and, under
`forward`, hand those bodies to the upstream unredacted; over-inclusion here is a leak, not a
compatibility win. Leaving the behavior documented-but-broken was rejected for the same reason the
body case was: a signature honmoon breaks itself is an opaque upstream failure at the far end of a
TLS-terminated tunnel.

**The decision point is after redaction has been computed**, i.e. only when `outcome.redacted` is
true. A signed request with nothing to redact is forwarded byte-identical and logs nothing, so
signed traffic that carries no secrets is entirely unaffected.

**The policy is a gateway-wide flag, `--signed-body <block|forward>`, defaulting to `block`**
(`SignedBodyMode` on `RedactionState`; requires `--redact-secrets`):

- `block` answers the client locally with `403`, an `X-Honmoon-Reason: signed-body-redaction`
  header, and a plain-text explanation naming the scheme and the escape hatch, and records an
  audit event (`Decision::Denied`, `Verdict::Deny`, rule `wire-redaction/signed-body`). The
  secret is never sent, and an opaque upstream signature failure becomes an actionable local one.
- `forward` returns the original request untouched — same bytes, same headers, no mapping recorded
  — mirroring the existing `Content-Range` fail-open branch, for operators who trust the signed
  upstream more than they fear the leak.

`block` is the default because it is the only mode that preserves the guarantee `--redact-secrets`
is bought for: a flag the operator turned on to stop secrets crossing the wire must not silently
let them cross for a subset of traffic.

Per-endpoint or per-host signed-body policy is deferred. The current policy engine expresses
egress and PII verdicts, not redaction transport behavior, and a single gateway-wide switch is
enough to unblock the two known shapes (signed uploads vs. bearer-token API traffic).

## Consequences

- A SigV4-signed request — an S3 `PutObject` with a payload hash, a signed API call — whose body
  contains a detected secret or Tier-1 PII is **refused** by default. Operators who need those
  uploads to go through must remove the sensitive value or opt in with `--signed-body forward`.
  This is a behavior change for anyone running `--redact-secrets` against signed upstreams, but
  the previous behavior was an upstream rejection anyway, only less legible.
- S3 uploads using `UNSIGNED-PAYLOAD` (the common browser/SDK streaming path) stay redactable when
  their `SignedHeaders` list leaves the framing headers alone — the exception is what keeps the
  default from being disruptive. Their `Accept-Encoding` is preserved, because SigV4 signs headers
  even when it does not sign the payload. An upload that *does* sign `content-length` or
  `content-encoding` — the common AWS SDK shape — is refused (or forwarded intact under `forward`)
  rather than rewritten into an opaque upstream signature failure: `block` costs those uploads the
  same visible `403` a body-signed request gets, which is a behavior change from the release that
  rewrote them and let the upstream reject them (#83).
- Detection of a covered header is as header-shaped as the body detection: a scheme we do not
  recognize whose signature covers `Content-Length` still breaks under redaction, exactly as it
  does for the body.
- `forward` is a genuine fail-open hole and is logged at `warn` on every use, alongside the other
  redaction bypasses.
- Every body-signed request keeps the client's `Accept-Encoding` — the usual `identity`
  negotiation is skipped for them because some SigV4 signers list that header in `SignedHeaders`,
  and the request is either forwarded as signed or answered locally with a `403`. So the response
  may come back compressed and is then not detokenized, which is the existing behavior for any
  compressed response.
- Detection is header-shaped and therefore approximate: a scheme we do not recognize whose
  signature covers the body still breaks under redaction (as it does today), and a request that
  merely *looks* signed is blocked. New schemes are one match arm in `signed_body.rs`.
- Re-signing on the gateway is rejected as a design direction. If a future release revisits it, it
  needs its own ADR covering credential custody, not an extension of this one.
