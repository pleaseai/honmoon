# ADR-0009: Request inspection covers bodies only; header-shaped fields are out of contract

## Status

Accepted (2026-09-11, #133).

## Context

Honmoon's request pipeline scans request **body** bytes. `inspect_body` buffers the body,
`decode_strict` decodes a declared `Content-Encoding`, `utf8_prefix` turns the result into text,
and `detect_spans` produces the `pii.*` facts a policy rule can condition on. Wire redaction
(`--redact-secrets`) runs `detect_secrets` over the same body text and rewrites those bytes.
Nothing in the pipeline reads a `HeaderMap`.

That leaves **request trailers** — the chunked trailer section, `Trailer: X-Note` plus
`0\r\nX-Note: <secret>\r\n\r\n` — forwarded to the upstream unscanned, unredacted and unaudited.
`facts.pii` stays empty, so a `pii.count > 0` rule cannot fire on trailer content.

### #130 did not create this

Tracing the four branches of `inspect_body`'s `content_length` match **before** #130 (verified
against the source, not assumed):

| Branch | Pre-#130 trailer behavior | Post-#130 |
| --- | --- | --- |
| `Some(len) <= MAX_INSPECT_BODY` | rebuilt with `Full` — trailers dropped | forwarded via `buffered_body` |
| `Some(len) > MAX_INSPECT_BODY` | body forwarded untouched — **trailers already passed through** | unchanged |
| `None` within cap | rebuilt with `Full` — trailers dropped | forwarded via `buffered_body` |
| `None` over cap (`Buffered::Overflow`) | `prefixed_body` delegates to the untouched `rest` — **trailers already passed through** | unchanged |

Two of four paths already forwarded trailers unscanned. Dropping trailers on the other two was
never a control — it was an artifact of `Full` carrying no trailers. #130 widened *reachability*
of an existing gap to the common buffered case; it did not open a class of bypass.

### The parity argument, and where it actually points

The gap is at parity with request **headers**, which honmoon has never scanned either. The same
secret in a plain `X-Note:` header was always forwarded untouched. Against a deliberate adversary
— a prompt-injected or compromised agent trying to exfiltrate — trailer scanning is strictly
dominated: the header is simpler, and closing only the trailer position moves the secret one field
up. Against accidental disclosure, secrets do not land in trailers by accident; they land in
bodies (covered) and in credential headers (intended).

So the severity is Low, and the real defect is not in the data plane. It is that the contract was
never stated. `README.md`'s **"Wire redaction fail modes"** section enumerated exactly four ways
content reaches the upstream unredacted — over-cap bodies, non-UTF-8 bodies, undecodable
`Content-Encoding`, `Content-Range` partial uploads — and said each logs a `warn`. A reader takes
a section titled "fail modes" as exhaustive for *how can content reach the upstream unredacted?*
It was not, and the difference is material in two ways:

- Each listed mode **fails open loudly** (a `warn`). Header-shaped fields fail open **silently** —
  no warn, no audit record, nothing.
- Each listed mode is a case where honmoon *tried and could not*. Header-shaped fields were never
  in scope, so there is nothing to fail — which is precisely why no warn exists, and precisely why
  the omission did not occur to anyone.

## Decision

**The request inspection contract covers request bodies only.** Header and trailer values are
never scanned for PII or secrets, never redacted, and are forwarded to the upstream verbatim. No
`warn` is logged for them, because nothing was attempted — they are outside the contract rather
than a failure within it.

This is recorded in three places so it cannot be rediscovered as a surprise:

1. `README.md`, in the "Wire redaction fail modes" section, which now distinguishes the four
   loud fail-open cases from the silent out-of-contract surface.
2. Module documentation on `inspect_body` and on `buffer_up_to`/`buffered_body` — at the point in
   the code where trailers are preserved, so the next reader of that code sees the boundary
   without leaving the file.
3. `trailer_content_is_outside_the_inspection_contract` in `crates/honmoon-proxy/tests/redaction.rs`,
   which pins the boundary end to end, paired with a control test proving the same rule *does*
   refuse the same content in the body. The pair makes the boundary executable: widening the scan
   later fails the test and forces the contract change to be deliberate.

Scanning header-shaped fields remains a **separate, open product decision**, not an implied
obligation deferred by this ADR.

## Consequences

**What this guarantees.** A reader of the fail-modes section now gets a complete answer to "how can
content reach the upstream unredacted?". The threat model has one stated boundary rather than an
enumeration that reads as exhaustive and is not.

**What this does not guarantee.** Nothing about the data plane changed. An agent that puts a secret
in a trailer — or in a header — still reaches the upstream with it, on every one of the four
branches above. Operators who need to constrain that surface have the existing levers: keep
`egress.default: deny` so only allow-listed hosts are reachable at all, and treat header-shaped
fields as uncontrolled.

**If scanning is added later**, the contract text and the pinning test are the things to change
first, deliberately. Two properties must be settled at that point and are not settled here:
trailers are only *visible* to the scanner on the two buffered branches (the over-cap branches
never read them), and trailer content cannot be redacted without breaking the byte-fidelity
`--signed-body forward` promises for a signature covering a `Content-Digest` trailer (ADR-0006).
A scan that covers two of four paths and cannot redact what it finds is a weaker guarantee than
the one its presence would imply.

**Relationship to the open trailer issues.** This ADR constrains none of them, but it does place
one: #134 (h2 trailer allowlist) becomes the natural home for *controlling* trailer content,
because an allowlist restricts which trailers cross the boundary without claiming to understand
their values — which is the lever this contract leaves available. #135 (stale `Trailer` header
after a redaction rewrite) and #136 (h2 `Content-Length` trailers dropped on an h1 upstream) are
framing and transport-mapping bugs, independent of whether values are inspected.

## Alternatives Considered

- **Scan trailer values alongside the body before the policy decision.** Rejected. It closes
  nothing against the adversary it would be defending against — that adversary uses the header,
  which is simpler and already unscanned — while implying to the operator that honmoon understands
  header-shaped fields. It would also be a *partial* scan in two independent ways: only the two
  buffered branches ever see trailers, and detection without redaction means a finding on a signed
  request can be reported but not acted on without breaking the signature. A guarantee that holds
  on half the paths and cannot remediate is worse than a clearly stated absence, because the
  operator stops looking.

- **Scan request headers as well, for consistency.** Rejected here as out of scope, and noted as a
  real product decision with real cost rather than an oversight. Header content is largely protocol
  machinery (`Authorization`, `Cookie`, content negotiation); a naive scan would fire on every
  intended credential, and a scan that excludes credential headers is an allowlist exercise whose
  design belongs in its own issue.

- **Log a `warn` when a forwarded request carries trailers**, making the silent fail-open loud
  without scanning. Rejected because it inherits the same partial-coverage flaw as a partial scan,
  inverted: the warn could only be emitted on the two buffered branches, so it would be *absent*
  exactly on the over-cap paths where trailers also pass through. A signal that is missing where
  the surface is widest is worse than no signal, because its absence reads as "no trailers". It
  would also fire on ordinary gRPC traffic, where trailers are protocol machinery.

- **Leave the behavior undocumented and close #133 as working-as-intended.** Rejected. The
  behavior is intended, but "intended" was not written down anywhere, and the fail-modes section
  actively implied otherwise. The whole value of this issue is the contract statement.
