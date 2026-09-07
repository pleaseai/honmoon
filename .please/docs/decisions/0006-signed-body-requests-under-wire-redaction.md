# ADR-0006: Body-signed requests under wire redaction

## Status

Accepted.

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

Re-signing is the other direction one could take: give the gateway the client's AWS credentials
and have it produce a fresh SigV4 signature over the redacted body. That turns the gateway into a
credential holder for every signed upstream an agent talks to, which is a larger blast radius than
the problem being solved and contradicts the design premise that honmoon sees traffic but not
long-lived secrets.

## Decision

**Detect only schemes whose signature actually covers the body**, in
`honmoon-proxy::signed_body::body_signature_scheme`:

- **AWS SigV4** — an `Authorization` starting with `AWS4-HMAC-SHA256` or `AWS4-ECDSA-P256-SHA256`
  (SigV4A), a presigned `X-Amz-Algorithm=AWS4-…` query parameter, or a bare hex
  `x-amz-content-sha256` payload hash. **Exception:** `x-amz-content-sha256: UNSIGNED-PAYLOAD` or
  `STREAMING-UNSIGNED-PAYLOAD…` declares the body explicitly out of the signature, so those stay
  redactable.
- **RFC 9421 message signatures** — `Signature-Input` naming a `"content-digest"` component.
  Without that component the signature does not cover the body.
- **draft-cavage** — `Signature` whose `headers="…"` list contains `digest` or `content-digest`.

Everything else — bearer tokens, Basic auth, API keys, bare digest headers — is not body-signed
and keeps being redacted.

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
- S3 uploads using `UNSIGNED-PAYLOAD` (the common browser/SDK streaming path) keep working, with
  redaction applied — the exception is what keeps the default from being disruptive.
- `forward` is a genuine fail-open hole and is logged at `warn` on every use, alongside the other
  redaction bypasses.
- Detection is header-shaped and therefore approximate: a scheme we do not recognize whose
  signature covers the body still breaks under redaction (as it does today), and a request that
  merely *looks* signed is blocked. New schemes are one match arm in `signed_body.rs`.
- Re-signing on the gateway is rejected as a design direction. If a future release revisits it, it
  needs its own ADR covering credential custody, not an extension of this one.
