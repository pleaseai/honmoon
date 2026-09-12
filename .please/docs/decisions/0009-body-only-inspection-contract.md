# ADR-0009: Request inspection covers bodies only; header-shaped fields are out of contract

## Status

Accepted (2026-09-11, #133). Amended 2026-09-12 (#134): honmoon now refuses to *forward* a request
trailer whose field name could change how the recipient frames, routes or authenticates the
request. The inspection contract below is unchanged — the filter reads names, never values — but
the forwarding clauses it states conditionally gained a second condition, and they are corrected in
place. ADR-0006 was amended in the same change, since `--signed-body forward` no longer reproduces
such a trailer.

## Context

Honmoon's request pipeline scans request **body** bytes. `inspect_body` buffers the body,
`decode_strict` decodes a declared `Content-Encoding`, `utf8_prefix` turns the result into text,
and `detect_spans` produces the `pii.*` facts a policy rule can condition on. Wire redaction
(`--redact-secrets`) runs `detect_secrets` over the same body text and rewrites those bytes.
No detector in the pipeline ever runs over a `HeaderMap`. Headers are certainly *read* —
`inspect_body` takes `Content-Length`, `Content-Type` and `Content-Encoding` off them to decide
framing and decoding, signature detection reads `Authorization` and its relatives, and the
redaction rewrite re-frames several — but only ever as protocol metadata. No header or trailer
*value* is passed to `detect_spans` or `detect_secrets`.

That leaves **request trailers** — the chunked trailer section, `Trailer: X-Note` plus
`0\r\nX-Note: <secret>\r\n\r\n` — unscanned and unredacted, and on a request honmoon does not
rewrite, passed to the upstream that way. `facts.pii` stays empty, so a `pii.count > 0` rule cannot
fire on trailer content, and nothing a *positive* finding would have caused — no deny, no pause, no
audit attributable to the secret — happens. (An absence rule such as `pii.count == 0` still fires;
it simply reads the request as clean. A matching `deny`/`pause` records its verdict like any other,
while a matching `allow` stays unaudited, since `inspect_body` records a clean Allow only when
`pii.count > 0`. See Consequences.)

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
  no warn about what they carry, and nothing a positive-finding rule can act on. (Not *nothing at
  all*: the engine always binds `pii` with its empty default so absence conditions work, so a
  `pii.count == 0` rule still fires and still audits its verdict — it just reads the request as
  clean. See Consequences.)
- Each listed mode is a case where honmoon *tried and could not*. Header-shaped fields were never
  in scope, so there is nothing to fail — which is precisely why no warn exists, and precisely why
  the omission did not occur to anyone.

## Decision

**The request inspection contract covers request bodies only.** Header and trailer values are
never scanned for PII or secrets and never redacted. No `warn` is logged about their *contents*,
because nothing was attempted — they are outside the contract rather than a failure within it. Two
of the four fail-open warns above are *triggered* by a header — `Content-Range`'s presence, an
unparseable `Content-Encoding` — but each one reports a skipped *body* rewrite, never a header or
trailer value that went unscanned.

**That is a statement about inspection, not about forwarding**, and conflating the two would
overclaim. Whether a trailer *reaches* the upstream has a conditional answer:

- On the **pass-through path** — every request honmoon does not rewrite — the trailer frame is
  replayed, minus any field whose **name** a trailer section must not carry. Since #134,
  `trailer_filtered_body` drops the names that could change how the recipient frames, routes or
  authenticates the request — framing (`Transfer-Encoding`, `Content-Length`), routing (`Host`),
  authentication (`Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`,
  `Cookie`, `Set-Cookie`), content processing (`Content-Encoding`, `Content-Type`, `Content-Range`,
  `Trailer`), the three request modifiers hyper's h1 encoder already refuses (`Cache-Control`,
  `Max-Forwards`, `TE`), the RFC 9113 §8.2.2 connection-specific names (`Connection`, `Keep-Alive`,
  `Proxy-Connection`, `Upgrade`) and whatever the request's `Connection` header nominates — logging
  a `warn` that names what it dropped and where it was bound. It deliberately does **not** drop the
  conditionals, `Range`, `Expect`, `Pragma` or the `Accept*` family, which a trailer section may not
  carry either but which change only what the recipient returns; the criterion and that exclusion
  are recorded on `FORBIDDEN_TRAILER_FIELDS`. That is a name decision and not a value one, so it
  neither widens nor narrows the inspection contract: honmoon still reads no trailer value. It runs
  on all four branches of `inspect_body` and before the upstream protocol is known, which is the
  point — and it is not redundant on either leg, since hyper's h1 encoder refuses only its own
  12-name enumeration and nothing applied even that on an h2 upstream leg.
- When `--redact-secrets` **rewrites the body**, `forwarded_request` replaces it with `Full`, which
  carries no trailer frame, so the client's trailers are **dropped**. That is deliberate and
  fail-safe: a digest the client computed over the original bytes is stale once those bytes are
  replaced, whether it rode in a header or a trailer — the same reasoning that strips
  `BODY_DIGEST_HEADERS`. (The `Trailer:` declaration header left behind by that drop is #135.)
- What finally crosses is then subject to the upstream leg's own framing rules (#136).

None of that changes the inspection contract: a dropped trailer was not inspected either.

This is recorded in three places so it cannot be rediscovered as a surprise:

1. `README.md`, in the "Wire redaction fail modes" section, which now distinguishes the loud
   redaction cases — the four fail-opens and the partial JSON skip — from the silent
   out-of-contract surface.
2. Module documentation on `inspect_body` and on `buffer_up_to`/`buffered_body` — at the point in
   the code where trailers are preserved, so the next reader of that code sees the boundary
   without leaving the file.
3. `trailer_content_is_outside_the_inspection_contract` in `crates/honmoon-proxy/tests/redaction.rs`,
   which drives the boundary through the full proxy stack, paired with a control test proving the
   same rule *does* refuse the same content in the body. The pair makes the boundary executable:
   widening the scan later fails the test and forces the contract change to be deliberate.

   That pair pins **one** of the four branches — the unknown-length within-cap (chunked) one, which
   is what an HTTP/1 harness can express, since HTTP/1 carries trailers only under chunked framing.
   The others are argued rather than pinned, and deliberately so: `mitm.rs`'s
   `forwarded_body_keeps_trailers_on_the_content_length_path` already covers trailer *preservation*
   on the `Content-Length` branch but pairs it with no `pii.count` rule, and on the two over-cap
   branches the body itself is not scanned either, so there is no inspection for a trailer to be
   excluded from. A regression that started scanning trailers on the `Content-Length` branch alone
   would therefore pass the suite — the narrowest real gap this contract leaves, and the first
   thing to close if that branch ever grows its own inspection path.

Since #134, `mitm.rs`'s `forbidden_trailers_are_dropped_on_the_*` tests drive all four branches of
that same `content_length` match through `inspect_body`. They pin the *forwarding* filter on each
of them and say nothing about inspection, so they neither close nor narrow the gap point 3
describes — that boundary is still pinned by point 3 alone.

Scanning header-shaped fields remains a **separate, open product decision**, not an implied
obligation deferred by this ADR.

## Consequences

**What this guarantees — and the claim it deliberately stops making.** This ADR states one
boundary: **the inspection contract covers request bodies only.** That claim is exhaustive and is
the thing to rely on.

It does **not** claim to enumerate every way content can reach the upstream unredacted. The
fail-modes section said it did, and each review round found another path it had missed, which is
the evidence that the claim was the wrong shape rather than merely incomplete. The paths known
today are recorded below, and the list is offered as known-incomplete:

- **Never intercepted.** The SOCKS5 raw tunnel, and a CONNECT tunnel without `--tls-intercept`,
  gate on `domain` and inspect nothing at all — whole bodies included. The README documents that
  as a second egress path in its own right.
- **Partial redaction, JSON syntax.** When an `application/json` body carries PII in an **unquoted
  numeric value**, `quoted_json_spans` skips that span so the rewrite cannot emit invalid JSON: the
  rest of the body is redacted, the skipped value reaches the upstream verbatim, and a `warn` names
  the count (`mitm.rs:449`; test `unquoted_numeric_json_pii_is_not_rewritten`).
- **Partial redaction, severity floor.** `DEFAULT_MIN_PII_SEVERITY` is MEDIUM, so a finding below
  it — a bare IPv4 address is the standing example — is detected and deliberately left in place. If
  it is the body's *only* finding, `outcome.redacted` is false and `forwarded_request` returns the
  request unchanged with **no** redaction `warn` (test
  `min_severity_gate_skips_low_severity_ip_by_default`, `redact.rs:209`).

The last two are unlike the header-shaped fields this ADR is about, and the difference is the whole
point of the distinction drawn here: those values *were* scanned, so they count toward `pii.count`,
an audit records them, and a `pii.count > 0 -> deny` under `--pii-mode block` refuses the request.
What fails there is the rewrite, not the inspection. For a header or a trailer, nothing is scanned
and no positive-finding rule can fire at all.

**What this does not guarantee.** Nothing about the data plane changed. What *reaches* the upstream
turns out to be conditional in enough independent ways that every attempt to state it in one
sentence has been wrong, so it is enumerated instead. **Every row below describes an intercepted
HTTP request**; on the raw-tunnel path none of it applies, because nothing there is inspected:

| Field | Scanned for PII or secrets? | Does it reach the upstream? |
| --- | --- | --- |
| Request body | Yes — but only one that is buffered within the 2 MiB cap, decodes within it (or, when the declared encoding is unusable, falls back to its raw bytes), and reads as UTF-8 text (see the note below) | Rewritten when redaction fires |
| Ordinary header (`X-Note:`) | **Never** | Yes |
| Body-digest header (`Digest`, `Content-Digest`, `Content-MD5`, `Repr-Digest`) | **Never** | Stripped when the body is redacted |
| Framing header (`Content-Length`, `Content-Encoding`, `Transfer-Encoding`) | **Never** — read as metadata only | Re-framed when the body is redacted |
| Request trailer | **Never** | Only on a pass-through request, only for a field name honmoon's #134 filter does not refuse, and only where the upstream leg's framing carries trailers at all (see issue #136). This is the one right-hand-column row that also constrains `--signed-body forward` (ADR-0006) |

**The body row's "yes" is itself conditional.** Three conditions mean no finding is possible at
all. An over-cap body never reaches the scanner (`scanned` is `None`); a decoded body that
overflows the cap is discarded rather than judged on a truncated prefix (`StrictDecode::Overflow` →
`inspected: None`); a body with *interior* invalid bytes is rejected **before** the scanner, since
`inspect_body` runs `utf8_prefix` first and `detect_spans` never sees a `None`. That last one is
narrower than "non-UTF-8": a merely truncated trailing multi-byte sequence is tolerated, and the
valid prefix ahead of it *is* scanned, so a secret sitting in that prefix is still found. Where the three do bite, `pii` ends up empty, so `pii.count > 0` cannot
block them any more than it can block a trailer — the `warn` is the only thing that marks them.

**Two of the fail-open cases are redaction-only, and those bodies do reach the scanner** — do not
read the fail-open list as a list of uninspectable requests. A partial upload carrying
`Content-Range` is not exempt from inspection: `decide_explained` runs on it in `inspect_body`
before `forwarded_request` is reached, and the `Content-Range` check there skips only the rewrite.
Detector coverage is then exactly what the three conditions above allow — an over-cap partial
upload, or one whose bytes do not read as text, yields no findings, like any other body of that
shape. An undecodable
`Content-Encoding` falls back to scanning the raw bytes, deliberately, so a plaintext body cannot
evade the scan by claiming to be compressed — but that fallback only catches the
mislabelled-plaintext case: genuinely compressed bytes normally fail `utf8_prefix` like any other
binary body and yield no finding. Normally, not always — `utf8_prefix` rejects interior invalid
bytes, so a compressed stream that happens to be valid UTF-8 throughout is scanned as text. Treat
the fallback as opportunistic, not as coverage. Where the scan does find something, a `pii.count > 0 -> deny` rule
acts on it as usual — enforced under `--pii-mode block`, and under the **default** `detect` mode
recorded as the would-be verdict and forwarded (`decide_pii_audit_only`). What fails open in both
is the wire rewrite, not the inspection.

**Only the middle column is this ADR's contract.** The right-hand column is transport behaviour that
varies with the redaction path and the upstream protocol, and most of it presupposes
`--redact-secrets`: without it no rewrite happens, so nothing is stripped or re-framed and a
trailer survives every branch of `inspect_body` — still subject, as everywhere in the right-hand
column, to whether the upstream leg's framing carries trailers at all (#136), and to the #134 name
filter, which is the one part of that column that runs whether or not `--redact-secrets` is on. It is recorded so that nobody reads the middle column as a delivery guarantee, which
is the error this document kept making about itself.

**And `pii.count == 0` does not mean "no secrets here".** `eval_program` always binds `pii` with
its empty default so absence conditions can be written at all, so an unscanned trailer leaves the
facts indistinguishable from a genuinely clean body. A positive-finding rule (`pii.count > 0`, a
`pii.types` match) simply never fires on trailer content; an **absence** rule fires and reads the
request as clean, so `pii.count == 0 -> allow` allows a request carrying a secret in a trailer, and
a matching `deny`/`pause` audits it like any other verdict. Policies meant to act on content should
condition on positive findings. And there is no *content-level* lever to point operators at: `egress.default: deny`
narrows which hosts are reachable and is worth keeping, but it scans nothing, so an allow-listed
destination — the API the agent exists to call, and exactly where an exfiltration attempt would go
— still receives header and trailer content unexamined. The honest instruction is to treat
header-shaped fields as uncontrolled, not to present a destination control as if it covered them.

**If scanning is added later**, the contract text and the pinning test are the things to change
first, deliberately. The property that must be settled then, and is not settled here, is
**coverage**: trailers are only visible *in time to decide* on the two buffered branches — the
over-cap branches have not read them when `decide_explained` runs — so a scan lands on two of four
paths and is silently absent on the rest. A guarantee that holds on half the paths is weaker than
the one its presence implies. #134's filter is not a counter-example: it sees the trailer frame on
every branch precisely because it runs *later*, while the body streams upstream, which is after the
verdict is fixed. Seeing a trailer in time to drop it by name and seeing one in time to let it
change a verdict are different problems, and only the first is solved.

**Redaction of a found trailer is a smaller obstacle than it first appears**, and that is worth
stating plainly here because this document is what a future implementer will weigh. On an
**unsigned** request — the overwhelming majority of agent traffic — a buffered trailer is a plain
owned `HeaderMap` by that point and could be rewritten exactly like a body value. On a
**body-signed** request, a trailer rewrite is the same class of change as a body rewrite and falls
through the gate `forwarded_request` already applies: `SignedBodyMode::Forward` fails open with a
`warn`, `SignedBodyMode::Block` refuses with a 403 and an audit record (ADR-0006). It needs no new
mechanism and breaks no promise that body redaction does not already break. Coverage is the
load-bearing objection; redaction is not.

**Relationship to the open trailer issues.** This ADR constrains none of them, but it did place
one: #134 (h2 trailer allowlist) was the natural home for *controlling* trailer content, because a
name filter restricts which trailers cross the boundary without claiming to understand their
values — the lever this contract leaves available. #134 has since landed, and what it built is a
**denylist of forbidden names, not an intersection with the client's `Trailer:` declaration**. The
reasoning is the one this document already records about `Trailer:` being advisory and routinely
omitted: an attacker who wants `transfer-encoding` forwarded simply declares
`Trailer: transfer-encoding`, so the intersection stops nothing it is the only thing stopping,
while it would silently drop the undeclared trailers honest HTTP/2 clients send — including a
`Content-Digest` an RFC 9421 signature covers under `--signed-body forward` (ADR-0006). The
forbidden-name list does the whole of the security work; the intersection only has a cost. #135 (stale `Trailer` header
after a redaction rewrite) and #136 (h2 `Content-Length` trailers dropped on an h1 upstream) are
framing and transport-mapping bugs, independent of whether values are inspected.

## Alternatives Considered

- **Scan trailer values alongside the body before the policy decision.** Rejected. It closes
  nothing against the adversary it would be defending against — that adversary uses the header,
  which is simpler and already unscanned — while implying to the operator that honmoon understands
  header-shaped fields. It would also be a *partial* scan: only the two buffered branches ever see
  trailers, so the guarantee would hold on half the paths and be silently absent on the rest —
  worse than a clearly stated absence, because the operator stops looking. Redacting what such a
  scan found is **not** a second, independent obstacle — see Consequences; the existing
  `--signed-body` gate already covers that class.

- **Scan request headers as well, for consistency.** Rejected here as out of scope, and noted as a
  real product decision with real cost rather than an oversight. Header content is largely protocol
  machinery (`Authorization`, `Cookie`, content negotiation); a naive scan would fire on every
  intended credential, and a scan that excludes credential headers is an allowlist exercise whose
  design belongs in its own issue.

- **Log a `warn` when a forwarded request carries trailers**, making the silent fail-open loud
  without scanning. Rejected, and the reason matters because the obvious one is wrong. A warn
  driven by an observed trailer *frame* could only be emitted on the two buffered branches, absent
  on the over-cap paths where trailers also pass through — but a warn driven by the request's
  `Trailer:` **declaration header** carries no such limit: headers are fully parsed before the
  `content_length` match and `parts` survives it, so all four branches could emit one. The real
  objection is that `Trailer:` is advisory and routinely omitted — HTTP/2 clients generally do not
  send it — so a declaration-driven warn is trivially switched off by the same adversary it
  watches for, while still firing on ordinary gRPC traffic where trailers are protocol machinery.
  A signal the adversary can disable and the honest client cannot is not a control.

  *Amended (#134).* The frame-driven half of that reasoning was wrong about mechanism, though not
  about the conclusion. A body adapter wrapping the forwarded body observes the trailer frame on
  **all four** branches, because it is polled while the body streams upstream rather than before
  the verdict — which is how `trailer_filtered_body` filters the over-cap paths at all. So a
  frame-driven warn was always possible; what it could never be is *an input to the decision*,
  since it arrives after the decision. Honmoon does emit a `warn` there now, but only when it
  actually drops a field — reporting an action it took, like the other fail-open warns, rather
  than narrating that a trailer went by.

- **Leave the behavior undocumented and close #133 as working-as-intended.** Rejected. The
  behavior is intended, but "intended" was not written down anywhere, and the fail-modes section
  actively implied otherwise. The whole value of this issue is the contract statement.
