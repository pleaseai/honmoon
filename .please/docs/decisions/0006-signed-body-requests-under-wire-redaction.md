# ADR-0006: Body-signed requests under wire redaction

## Status

Accepted. Amended 2026-09-11 (#81): SigV4 body-signature detection is narrower than originally
recorded — a presigned URL and a bare `x-amz-content-sha256` payload hash no longer count on their
own. The Decision below is the current rule; the reasoning for the change is in the Context and
Consequences.

Amended 2026-09-12 (#134): `forward`'s "untouched" is no longer unqualified. A trailer whose field
name a trailer section must not carry is dropped before the request leaves honmoon, by a filter
that runs ahead of — and independently of — every decision this ADR describes. The qualification is
stated where each claim is made below.

Amended 2026-09-12 (#136): `forward`'s "same headers" is no longer unqualified either, and this
time the qualification *serves* the decision rather than costing it. A request carrying a trailer
section gains the two framing headers an HTTP/1.1 upstream leg needs in order to carry that section
— which is what lets a signed `Content-Digest` sent as a trailer survive the leg at all — and that
re-frame is declined for exactly the requests whose signature covers those headers. The clause and
the constraint it answers to are stated below.

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

Over-inclusion and under-inclusion are not symmetric, and the review of #80 (#81) found the
original SigV4 rule on the wrong side of that asymmetry for two of its three signals. Under the
default `block`, classifying a request as body-signed when it is not is merely disruptive — it
refuses traffic that could have been redacted and forwarded. Under `--signed-body forward` the
classification is what *disables* redaction, so the same over-inclusion is fail-open: a secret
leaves unredacted. A presigned `X-Amz-Algorithm` query parameter authenticates the *request* — a
standard S3 presigned URL puts `UNSIGNED-PAYLOAD` in its canonical request and binds no bytes —
and a bare `x-amz-content-sha256` is an integrity header, not a signature, with no AWS
authentication anywhere on the request to say who computed it. Neither carries a claim that a
signature covers the payload, and both are fully client-settable, so both were narrowed. The
same asymmetry justified requiring a matching `Signature` label for the RFC 9421 case in #80.

Re-signing is the other direction one could take: give the gateway the client's AWS credentials
and have it produce a fresh SigV4 signature over the redacted body. That turns the gateway into a
credential holder for every signed upstream an agent talks to, which is a larger blast radius than
the problem being solved and contradicts the design premise that honmoon sees traffic but not
long-lived secrets.

## Decision

**Detect only schemes whose signature actually covers the body**, in
`honmoon-proxy::signed_body::body_signature_scheme`:

- **AWS SigV4** — SigV4 authentication whose canonical request *hashed the payload*. The two
  carriers differ in what they bind, so they are treated differently (#81):
  - a header-signed `Authorization` starting with `AWS4-HMAC-SHA256` or `AWS4-ECDSA-P256-SHA256`
    (SigV4A) always hashes the payload into its canonical request — for non-S3 services the hash
    is not even sent as a header — so it counts on its own;
  - a presigned `X-Amz-Algorithm=AWS4-…` query parameter counts **only** alongside a payload hash
    that declares a signed payload: a 64-character hex SHA-256, or one of the four
    `STREAMING-AWS4-…-PAYLOAD[-TRAILER]` per-chunk signing markers, enumerated rather than
    prefix-matched so an invented `STREAMING-AWS4-…` value is not evidence. On its own the query
    parameter authenticates the request and the headers its `X-Amz-SignedHeaders` list names, not
    the bytes.

  The `x-amz-content-sha256` header is the authoritative carrier of that declaration — it is the
  value a signer hashes into the canonical request — and every field value of it counts. The
  `X-Amz-Content-Sha256` query parameter is read only when the request sends no such header *and*
  is presigned **and carries no `AWS4-…` `Authorization`**: presigning hoists the `x-amz-…` headers
  it signs into the query string, so a
  presigned upload that bound its payload may carry the hash there and send no header at all, and
  ignoring it would reach the `UNSIGNED-PAYLOAD` conclusion for a request that declared the
  opposite. A query parameter never contradicts the header, in either direction — otherwise an
  appended `?X-Amz-Content-Sha256=UNSIGNED-PAYLOAD` would have a signed body redacted and broken
  upstream, and on a header-signed request that parameter is a bare query argument the verifier
  never reads as the payload hash — and a header-signed credential carries its own payload hash in
  its canonical request, so a query argument cannot speak for it even when the credential signs that
  argument.

  **Exception:** `UNSIGNED-PAYLOAD` or `STREAMING-UNSIGNED-PAYLOAD…` declares the body explicitly
  out of the signature and wins over either carrier and either signal, so those stay redactable.
  And a payload hash with no SigV4 authentication on the request is **not** a body signature: it
  is an integrity check a client sets freely, and nothing on such a request claims a signature
  covers those bytes.
- **RFC 9421 message signatures** — a `Signature` header alongside `Signature-Input` (RFC 9421
  requires both; either may repeat across field values, all of which are scanned) whose component
  list names a body-digest header, under a label `Signature` actually carries. Labels are matched
  because both fields are dictionaries keyed the same way: a member naming a digest says nothing
  about a *different* member that is the one actually signed. A component's own `;param="…"` value
  is not a covered component, so `"@query-param";name="content-digest"` does not count.
- **draft-cavage** — a `Signature` header, or an `Authorization: Signature …` value, whose
  `headers="…"` parameter (tolerating whitespace around `=`) names a body-digest header.

**A signature over `x-amz-content-sha256` counts for those two schemes too**, when that header
carries a hex SHA-256 payload hash (#81). The `STREAMING-AWS4-…` markers do not count here, only on
the SigV4 path: they describe a body bound by *chunk* signatures derived from a SigV4 seed
signature, a construct that does not exist outside SigV4, so a message signature over that header
value fixes a string and binds no bytes. The value is a hash of the bytes, so signing it binds the body
exactly as signing `Content-Digest` does, and the scheme that signs it need not be SigV4 — an RFC
9421 or draft-cavage covered list can name it on a request with no AWS authentication at all. The
same header carrying `UNSIGNED-PAYLOAD` or `STREAMING-UNSIGNED-PAYLOAD…` is signed but binds
nothing, so that request stays redactable. This header is deliberately **not** in the body-digest
set below, because that set is also what the rewrite strips and honmoon must leave this one as the
client sent it: for a SigV4 request the signature covers it, and stripping it would break that
signature outright. The only difference the divergence makes is which failure a rewrite would
produce — a stale hash left in place describes bytes the upstream no longer receives, so the
upstream rejects on the payload hash rather than on the signature. Both are the opaque far-end
failure this ADR exists to prevent, so both take the same decision.

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
`transfer-encoding`) together with the `BODY_DIGEST_HEADERS` the request carries, which the same
rewrite strips as stale validators. Both constants are read by the rewrite and the detection alike,
for the reason `BODY_DIGEST_HEADERS` is. Only a header the rewrite would *actually* change counts:
a `Content-Encoding` the request never sent, a `Content-Length` the redacted body happens to match,
or a signed `Content-MD5` the client never sent, is left as the client signed it and does not block
anything. The digest half is what covers a SigV4 request that declares `UNSIGNED-PAYLOAD` and lists
`content-md5` in its `SignedHeaders` (#116): the body-signed branch correctly does not fire for it,
but the strip would break its signature all the same. RFC 9421 and draft-cavage signatures over a
digest never reach here — they are body-signed and take the earlier branch. A request that trips this
takes the same `--signed-body` decision as a body-signed one, under its own
`X-Honmoon-Reason: signed-header-redaction`, audit rule `wire-redaction/signed-headers`, and a
message naming the headers rather than the scheme.

Two coarser rules were rejected. Treating *any* header-signing authentication as body-signed would
refuse the entire `UNSIGNED-PAYLOAD` upload path — the case the exception exists for — and, under
`forward`, hand those bodies to the upstream unredacted; over-inclusion here is a leak, not a
compatibility win. Leaving the behavior documented-but-broken was rejected for the same reason the
body case was: a signature honmoon breaks itself is an opaque upstream failure at the far end of a
TLS-terminated tunnel.

Two narrower rules were rejected for the SigV4 carriers too (#81). **Making detection depend on the
mode** — the strict rule under `forward`, the old broad one under `block` — was rejected because it
makes the same request mean two different things and leaves `block` over-refusing presigned uploads
that were never body-signed, which is the usability half of the complaint. **Keeping both signals
and documenting the `forward` caveat more loudly** was rejected because a documented fail-open is
still a fail-open, and the signals it rests on are set by the client. What this detection does not
claim is forgery resistance: honmoon verifies no signature — it holds no keys — so a client that
writes its own `Authorization: AWS4-…` is still classified as body-signed. Narrowing removes the
two signals that assert nothing about a payload-covering signature; it does not turn the remaining
one into proof, and `forward` stays the documented fail-open hole it always was.

**The decision point is after redaction has been computed**, i.e. only when `outcome.redacted` is
true. A signed request with nothing to redact is forwarded with its body and headers byte-identical
and logs nothing, so signed traffic that carries no secrets is unaffected by *this* ADR's
machinery — with the one exception #134 introduced, below.

**The policy is a gateway-wide flag, `--signed-body <block|forward>`, defaulting to `block`**
(`SignedBodyMode` on `RedactionState`; requires `--redact-secrets`):

- `block` answers the client locally with `403`, an `X-Honmoon-Reason: signed-body-redaction`
  header, and a plain-text explanation naming the scheme and the escape hatch, and records an
  audit event (`Decision::Denied`, `Verdict::Deny`, rule `wire-redaction/signed-body`). The
  secret is never sent, and an opaque upstream signature failure becomes an actionable local one.
- `forward` returns the original request unchanged by redaction — same body bytes, no mapping
  recorded — mirroring the existing `Content-Range` fail-open branch, for operators who trust the
  signed upstream more than they fear the leak. Its headers are the client's too, with the one
  addition #136 introduces below.

**The one thing `forward` does not reproduce verbatim (#134).** `trailer_filtered_body` drops a
forwarded trailer whose field name a trailer section must not carry — framing, routing,
authentication, content-processing and connection-specific names (the list and its criterion are in
`crates/honmoon-proxy/src/body.rs`). It wraps the body in `inspect_body`, upstream of
`forwarded_request`, so it runs **before** and independently of the `SignedBodyMode` decision: a
`forward`-mode request loses such a trailer without the fail-open `warn` this ADR's branches emit,
and a `block`-mode one loses it without the `403`. It logs its own `warn` naming the dropped fields
and the destination.

That is a deliberate, bounded exception rather than an oversight. Every name on the list is one the
RFCs forbid in a trailer section and hyper's h1 encoder already refuses on that leg, so a signature
covering one was already unreproducible on an h1 upstream before honmoon existed; and forwarding a
framing token because a signature happens to cover it is exactly the laundering #134 exists to
stop. The trailer a signature realistically covers — `Content-Digest`, the RFC 9421 case this ADR
is written around — is **not** on the list and is unaffected, which
`signed_body_request_keeps_its_digest_trailer_in_forward_mode` pins. Reaching the upstream leg is a
second condition on top of surviving that filter, and since #136 honmoon supplies the framing it
needs — see the clause below.

**The two framing headers `forward` adds, and why they are not the trade this ADR refuses (#136).**
A trailer section reaches an HTTP/1.1 upstream only under chunked framing and only for the fields
the request's `Trailer` header names; HTTP/2 requires neither, and honmoon's own buffering hands
hyper an exact body length even when the client declared none. So a `Content-Digest` sent as a
trailer — the RFC 9421 case this ADR is written around — was being dropped on that leg, and
`forward` was reproducing a request the client had not signed. `framed_for_trailers` writes
`Transfer-Encoding: chunked` and the missing `Trailer` names onto a pass-through request that
carries a trailer frame, and hyper resolves the pair per-protocol, dropping whichever of
`Content-Length` / `Transfer-Encoding` its leg forbids.

That is a header change on a request this ADR promises to forward as signed, so it takes the same
constraint as every other one: `signed_headers_among` is asked about
`signed_body::TRAILER_FRAMING_HEADERS` (`content-length`, `transfer-encoding`, `trailer`), and a
signature over any of them **declines the re-frame** — the request goes on exactly as the client
framed it, and a `warn` names the covered headers alongside the trailers that will therefore not
arrive. The asymmetry with the rewrite is deliberate and is what keeps this consistent: the rewrite
*must* act once a secret is found, so it needs a block-or-forward flag to decide how; this re-frame
never has to act, so declining is a complete answer and needs no flag. The set is its own constant
rather than `REWRITTEN_FRAMING_HEADERS` because it is a different rewrite — `Content-Encoding` is
untouched here, since the body's bytes are, and `Trailer` is not something the redaction rewrite
ever writes.

What this leaves open, deliberately: when the signature covers a framing header *and* the trailer
field, honmoon has no option that preserves it, and it forwards as-is rather than refusing. Under
`--signed-body block` the operator arguably asked for the opposite. That is a new denial mode, not
this flag applied further — `SignedBodyMode` also lives on `RedactionState`, so routing through it
would make trailer framing depend on whether secret redaction is enabled — and it is tracked as its
own question (issue 178) rather than settled here.

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
- A presigned upload that carries no payload hash in either carrier, and a request whose only
  AWS-shaped signal is a payload hash, are **redacted and forwarded** rather than refused (#81). This is the
  weaker direction, and deliberately so: if such a request really was signed over its body by a
  scheme honmoon cannot see, the upstream now rejects the rewritten bytes with the opaque error
  this ADR exists to prevent. The cost is bounded to requests that present no evidence of a
  payload-covering signature, and it is the same limit the last bullet already accepts for
  unrecognized schemes. In exchange, the presigned upload path stops costing a `403` under the
  default, and `forward` no longer drops redaction on two client-settable signals.
- An operator who wants the old strictness for those two shapes cannot get it from `--signed-body`:
  they are no longer recognized, so neither mode acts on them. Recovering a refusal means denying
  the destination in policy (`egress`) for traffic that must never reach an upstream with a
  rewritten body — per-host signed-body policy stays deferred. `block` remains the default and
  still refuses every request whose signature does cover the payload or a framing header.
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
- Detection is header-shaped and therefore approximate in both directions: a scheme we do not
  recognize whose signature covers the body still breaks under redaction, and a request that
  presents a recognized scheme's evidence is treated as signed without that evidence being
  verified. New schemes are one match arm in `signed_body.rs`.
- Re-signing on the gateway is rejected as a design direction. If a future release revisits it, it
  needs its own ADR covering credential custody, not an extension of this one.
