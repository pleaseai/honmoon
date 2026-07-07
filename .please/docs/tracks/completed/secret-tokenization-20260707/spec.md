---
product_spec_domain: secret-tokenization
---

# Reversible Secret Tokenization (Core Primitive)

> Track: secret-tokenization-20260707

## Overview

Honmoon guards the boundary between AI agents and the third-party systems they talk to — an
LLM API being the motivating case. A recurring need is to keep a user's **secrets** (API keys,
tokens, passwords) out of the payloads that cross that boundary, while still letting the
agent's end-to-end workflow function. The approach is **reversible tokenization**: before a
request crosses the boundary, each registered secret is replaced with an opaque placeholder;
in the response, the placeholder is substituted back to the real secret.

This track delivers **only the core, transport-agnostic primitive** — a reusable tokenizer
that a later track will wire into the proxy's request/response bodies. Building the primitive
first de-risks the fragile round-trip semantics (especially reverse substitution over a
streamed response) behind fast, deterministic unit tests, with no networking involved.

The primitive lives in `honmoon-core` alongside the existing PII detector and follows the
same conventions. It has three responsibilities: register secrets and mint stable, opaque
placeholders, **tokenize** text (secret → placeholder), and **detokenize** text (placeholder
→ secret) — including a streaming detokenizer that is correct across arbitrary chunk
boundaries.

**Alternatives considered.** Reversible tokenization is chosen over never-sending the secret
(proxy-side injection keyed off a handle the model never echoes) and one-way redaction,
because the agent workflow frequently needs the model to reference the secret's value in-band
(e.g. composing a command that embeds it). The round-trip is the fragile part, which is
precisely why this track isolates and hardens it first. The fail-safe posture below (AC-014,
NFR-006) bounds the blast radius when the round-trip does not hold.

## User Scenarios & Testing

### User Story 1 — Round-trip a secret through opaque text (Priority: P1)

An operator registers one or more secret values. Given any text that contains those secrets,
the tokenizer produces text in which every occurrence is replaced by a stable, opaque
placeholder, plus a mapping. Given the placeholder-bearing text and that mapping, the
detokenizer reconstructs the original text exactly. This is the irreducible core: without a
faithful round-trip, nothing downstream is safe.

**Why this priority**: It is the minimum viable, independently useful unit. Every other
capability builds on a correct tokenize/detokenize pair.

**Independent Test**: In a unit test, register secrets, call `tokenize` on sample text,
assert no registered secret survives in the output and that placeholders are opaque, then call
`detokenize` with the returned mapping and assert the result equals the original input.

**Acceptance Criteria** (EARS):

1. **AC-001** — When text containing a registered secret is tokenized, the system shall
   replace every occurrence of that secret with its placeholder and return a mapping of the
   placeholders it actually substituted to their secrets.
2. **AC-002** — When placeholder-bearing text is detokenized with the mapping produced for it,
   the system shall reconstruct the original text exactly (`detokenize(tokenize(x)) == x`).
3. **AC-003** — The system shall not emit any registered secret value in tokenized output.
4. **AC-004** — Where a registered secret does not appear in the input text, the system shall
   leave the text unchanged and mint no mapping entry for that secret.

### User Story 2 — Reverse-substitute across a streamed response (Priority: P1)

A downstream consumer receives the response as an ordered sequence of chunks, and a
placeholder may be split across a chunk boundary (e.g. one chunk ends `…⟦hs:` and the next
begins `…⟧`). A streaming detokenizer accepts chunks in order and emits detokenized output,
buffering just enough of a trailing fragment that a placeholder straddling a boundary is still
recognized and substituted — and never emitting a partial placeholder as if it were final
text.

**Why this priority**: Real responses stream. A per-chunk substitution that ignores boundaries
would leak un-substituted placeholder fragments to the consumer, so streaming correctness is a
launch requirement, not a follow-up.

**Independent Test**: Take a full placeholder-bearing text and its expected detokenized form.
Feed the text to the streaming detokenizer under every possible single split point (and a set
of multi-split partitions), concatenate the emitted output per run, and assert each run equals
the expected form and that no run ever emits a partial placeholder token.

**Acceptance Criteria** (EARS):

1. **AC-005** — When a placeholder is split across two or more consecutive chunks, the
   streaming detokenizer shall recognize it and substitute the real secret.
2. **AC-006** — While chunks are still arriving, the system shall not emit a byte sequence
   that is the prefix of an as-yet-incomplete placeholder as final output.
3. **AC-007** — When the stream is finalized (flushed) and buffered bytes form only a *prefix*
   of a placeholder (never completed), the system shall emit those bytes verbatim as literal
   text and shall not emit any secret value.
4. **AC-008** — When chunks are concatenated, the streaming detokenizer's total output shall
   equal the output of detokenizing the whole text at once, for any chunk partition.

### User Story 3 — Deterministic, unambiguous substitution (Priority: P2)

Given the same registered secrets, the same session salt, and the same input, placeholder
assignment and matching are deterministic and free of ambiguity: the same placeholders and the
same output result every time, overlapping/substring secrets resolve by a defined rule
(leftmost-longest), and re-running tokenization over already-tokenized text does not
double-substitute.

**Why this priority**: Determinism (relative to explicit inputs) makes the primitive testable;
the overlap and idempotence rules close the correctness gaps that would otherwise surface only
as rare, hard-to-debug corruption once wired to live traffic.

**Independent Test**: Register two secrets where one is a substring of the other; tokenize
text containing the longer secret and assert the leftmost-longest match wins. Tokenize the
same input twice (feeding the first output back in) and assert placeholders are not
re-substituted.

**Acceptance Criteria** (EARS):

1. **AC-009** — Where the same registered secrets, the same session salt, and the same input
   are supplied, the system shall produce identical placeholders and identical output on every run.
2. **AC-010** — Where two registered secrets could match at the same position, the system shall
   substitute the leftmost-longest match, breaking length ties by registration order.
3. **AC-011** — When tokenized text is tokenized again, the system shall not substitute inside
   or across existing placeholders (no double-substitution).
4. **AC-012** — When a secret value is registered more than once within a session, the system
   shall reuse a single stable placeholder for that value rather than minting duplicates.

### User Story 4 — Provenance-bound, fail-safe reverse substitution (Priority: P1)

`detokenize` reintroduces a real secret into content that just crossed the trust boundary and
is therefore attacker-influenceable. Substitution must be bound to the placeholders this
session actually minted: a placeholder-shaped token that is not in the caller-supplied mapping
must never trigger a secret, and a mutated/incomplete placeholder must fail closed to literal
text. This prevents a *confused-deputy* leak where forged or guessed placeholder text in the
response coerces the primitive into disclosing a secret.

**Why this priority**: Without provenance binding, the primitive can be tricked into emitting a
secret it was meant to protect — defeating the feature's entire purpose. This is a launch
requirement, not a hardening follow-up.

**Independent Test**: Detokenize a response containing (a) a placeholder-shaped token absent
from the mapping and (b) a mutated near-match of a real placeholder; assert both are emitted
verbatim and no secret value appears in the output.

**Acceptance Criteria** (EARS):

1. **AC-013** — Where a placeholder-shaped token in the input is not present in the
   caller-supplied mapping, the system shall emit it verbatim and shall not substitute any
   secret value.
2. **AC-014** — If a placeholder is mutated such that it no longer exact-matches a mapping
   entry, then the system shall leave the surrounding text unchanged and shall not emit the
   real secret (fail closed).
3. **AC-015** — The system shall not include any registered secret value in its error messages,
   `Debug`/`Display` output, or serialized diagnostic output.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST let a caller register a set of secret values, scoped to a
  session, and mint a stable, opaque placeholder for each.
- **FR-002**: The system MUST replace every occurrence of a registered secret in a given text
  with its placeholder and return a mapping of the placeholders it actually substituted to
  their secrets (`tokenize`) — entries are minted only for secrets present in the text.
- **FR-003**: The system MUST reconstruct the original text from placeholder-bearing text and
  its mapping (`detokenize`), such that `detokenize(tokenize(x)) == x` for registered secrets.
- **FR-004**: The system MUST provide a streaming detokenizer that accepts ordered chunks and a
  finalize/flush step, and is correct when placeholders straddle chunk boundaries.
- **FR-005**: The system MUST resolve overlapping/substring secrets by leftmost-longest match,
  breaking length ties by registration order.
- **FR-006**: The system MUST be idempotent under re-tokenization (no double-substitution of
  existing placeholders).
- **FR-007**: Placeholders MUST have a fixed, documented structure — a distinctive delimiter
  pair unlikely to occur in ordinary payload text, enclosing an identifier that includes a
  per-session unpredictable component — and a known maximum length. The format MUST be opaque
  (it reveals nothing about the secret) and MUST NOT be forgeable by a party that does not hold
  the session's mapping.
- **FR-008**: `detokenize` MUST substitute only placeholders present in the caller-supplied
  mapping; any other placeholder-shaped token MUST pass through unchanged.

### Non-functional Requirements

- **NFR-001**: The primitive MUST reside entirely in `honmoon-core` with no `tokio`, socket, or
  other I/O dependency (honmoon-core is transport-agnostic — a hard architectural invariant).
- **NFR-002**: Placeholder assignment and all substitution MUST be deterministic **given their
  explicit inputs** (registered secrets, session salt, and text) — with no dependence on
  ambient wall-clock time or a global random source. Any unpredictable component (FR-007) is an
  explicit input (the session salt), so tests can pin it for reproducibility.
- **NFR-003**: The streaming detokenizer MUST bound the bytes it buffers across chunk
  boundaries to a fixed maximum (the maximum placeholder length from FR-007), so a hostile or
  unbounded stream cannot exhaust memory.
- **NFR-004**: The module MUST mirror the conventions of the existing PII module (serde types,
  inline `#[cfg(test)]` tests) and meet the project coverage target (>80%).
- **NFR-005**: Types that hold raw secret material MUST redact the secret in their
  `Debug`/`Display` output; the secret MUST NOT be recoverable from a logged or panicked value.
- **NFR-006**: The primitive MUST fail closed with respect to disclosure: in every path where a
  placeholder cannot be confidently matched to a mapping entry, the system MUST prefer emitting
  literal text over emitting a secret.

## Success Criteria

- **SC-001**: For registered secrets, detokenizing a tokenized text reproduces the original
  input with 100% fidelity across the test corpus.
- **SC-002**: A tokenized text contains none of the registered secret values (in their
  registered byte form).
- **SC-003**: Streaming detokenization produces output identical to whole-text detokenization
  for every chunk partition exercised, including every single-split point of the test corpus.
- **SC-004**: No test run ever emits a partial (incomplete) placeholder as final output, and no
  test run emits a secret for a forged or mutated placeholder.
- **SC-005**: Overlapping-secret and repeated-tokenization cases resolve exactly as specified
  (leftmost-longest, ties by registration order; no double-substitution) across the test corpus.

## Out of Scope (explicit follow-ups)

- Wiring the primitive into `honmoon-proxy`/`mitm.rs` request and response bodies, including
  scoping a mapping's lifetime to a single request/response exchange.
- A new policy verdict/action (e.g. `tokenize`/`redact`) and its CEL/policy surface.
- Wire-format parsing: rewriting inside JSON message bodies or SSE `data:` framing, and
  `Content-Length`/chunked-encoding fixups.
- Heuristic or entropy-based secret *detection* (this track uses exact-match of
  user-registered values only).
- **Encoded/transformed copies** of a registered secret (base64, URL-encoding, case-folding,
  whitespace-split) — a known residual gap of exact-match: SC-002 guarantees the *registered
  byte form* does not survive, not that no recoverable form does.
- The dual TypeScript policy model (`@honmoon/policy`) mirror.
- Secret storage/persistence and at-rest security hardening of the secret registry
  (lifecycle, encryption, rotation).
- Whether a placeholder survives the model verbatim (a prompt-side concern) — bounded here by
  the fail-safe contract (AC-014, NFR-006) but not otherwise enforced.

## Assumptions

- Callers supply secret values explicitly; the primitive does not discover secrets on its own.
  Callers are responsible for not registering trivially short or common strings as secrets;
  exact-match will otherwise over-substitute every incidental occurrence.
- The mapping produced by `tokenize` is supplied to the corresponding `detokenize` call (same
  session/request); cross-session persistence of the mapping is a later concern.
- Secrets and text are UTF-8; matching is over the byte/character content of the registered
  values, not semantic equivalence.
- The session salt (FR-007) is provided by the caller (or minted per session by the caller);
  this module treats it as an explicit input, keeping NFR-002 determinism testable.
- A fixed, known upper bound on placeholder length exists (it is a property of the FR-007
  format), which is what makes the streaming buffer bound in NFR-003 possible.
