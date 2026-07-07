# Plan: Reversible Secret Tokenization (Core Primitive)

> Track: secret-tokenization-20260707
> Spec: [spec.md](./spec.md)

## Overview

- **Source**: /please:plan
- **Track**: secret-tokenization-20260707
- **Issue**: (pending)
- **Created**: 2026-07-07
- **Approach**: One new `honmoon-core` module (`secret_tokenizer`) built around a stream-first
  detokenizer; whole-text detokenize wraps it. Placeholders are a keyed MAC of the secret under
  a per-session salt-key (unforgeable); matching uses `aho-corasick` leftmost-longest;
  secret-bearing types redact `Debug` and never derive `Serialize`.
- **Execution**: code
- **Plan Depth**: standard
- **Planned At**: 9679a9e

## Purpose

Deliver the transport-agnostic tokenize/detokenize primitive specified in `spec.md`, with the
fragile round-trip and streaming-reverse-substitution semantics fully unit-tested, so a later
track can wire it into `honmoon-proxy` without re-litigating correctness.

## Context

### Problem

Secrets (API keys, tokens, passwords) must be kept out of payloads that cross the agent↔third-
party boundary, while the agent workflow still functions. The mechanism is reversible
tokenization, whose fragile parts (streamed reverse substitution, provenance-bound disclosure)
need to be proven correct in isolation before any wire wiring.

### Requirements Summary

Register secrets → opaque, unforgeable placeholders (FR-001/FR-007); `tokenize` replacing all
occurrences and returning only substituted entries (FR-002, FR-005/FR-006); `detokenize` +
provenance binding (FR-003/FR-008); a boundary-safe streaming detokenizer (FR-004); fail-closed
disclosure and redacted secret types (NFR-005/NFR-006); determinism given explicit inputs
(NFR-002); transport-agnostic, no I/O dep (NFR-001); bounded streaming buffer (NFR-003). Full
AC/SC list in `spec.md`.

### Constraints

- `honmoon-core` MUST stay transport-agnostic — no `tokio`/socket/I/O dependency (NFR-001).
  (This is the binding constraint; crypto/matcher crates below are pure-CPU and do not violate it.)
- Mirror `pii.rs` conventions (module doc, inline `#[cfg(test)]` tests, LazyLock where useful) —
  **except** do not derive `Serialize`/`Deserialize` on secret-bearing types (see Architecture
  Decision; AC-015).
- Permitted dependencies (all already resolved transitively in the workspace lockfile, so no new
  crate enters the overall build graph): `aho-corasick` (multi-literal leftmost-longest matcher),
  `hmac` + `sha2` (keyed MAC for placeholder derivation). Add each as a direct dependency of
  `crates/honmoon-core/Cargo.toml`.

### Non-Goals

Proxy/`mitm.rs` wiring, policy action, JSON/SSE parsing, heuristic detection, the TS policy
model, secret persistence/at-rest hardening, and encoded-variant matching — all explicitly
deferred per `spec.md` → Out of Scope.

### Context notes

`crates/honmoon-core/src/lib.rs` exposes peer modules `audit`, `engine`, `pii`, `protocols` via
`pub mod` + `pub use`. The security core is provenance binding: `detokenize` substitutes **only**
placeholders present in the caller-supplied mapping (FR-008), and placeholder tokens are a keyed
MAC under the session salt (FR-007) so an attacker cannot predict a live placeholder and coerce
disclosure (the confused-deputy finding from spec + plan review).

### STOP Conditions

- **Matcher semantics (T002).** If `aho-corasick` `MatchKind::LeftmostLongest` does not, in a
  written test, reproduce FR-005/AC-010 (longest wins; equal-length ties → registration order),
  stop and reconsider the matcher before building on it — the whole substitution correctness
  rests here. (The plain `regex` alternation is known-insufficient: `regex` is leftmost-**first**,
  not leftmost-longest.)

## Architecture Decision

**Stream-first.** The whole-text and streaming detokenizers share one matcher, so implement the
streaming state machine (`StreamingDetokenizer`) as the engine and express whole-text
`detokenize` as `push(text)` + `finish()`. This guarantees AC-008 (streaming output == whole
output) by construction rather than by a second, drift-prone implementation. The streaming
matcher must **re-scan** buffered bytes after a false-start delimiter is invalidated, so a
`<<hs:<<hs:…` sequence (a false start immediately followed by a genuine placeholder start in the
same buffer window) is still recognized — a single linear tail-position counter is insufficient.

**Placeholder format.** A fixed **ASCII** sentinel (single-byte delimiters, to avoid multi-byte
codepoint-split concerns in the stream buffer): an opening delimiter, a fixed-width hex token,
and a closing delimiter (e.g. `<<hs:{N-hex}>>`). Properties: opaque, distinctive, fixed maximum
length (bounds the streaming buffer, NFR-003), and **unforgeable without the salt**. The token
is `HMAC-SHA256(key = session_salt, message = secret_bytes)` truncated to the fixed width —
deterministic given explicit inputs (NFR-002), unpredictable without the salt-key (FR-007). The
salt is used as the MAC **key**, not appended as hashed data; a non-keyed hash (e.g.
`DefaultHasher`, whose SipHash keys are the fixed public constant `(0,0)`) does **not** satisfy
FR-007 and is rejected.

**Matching (tokenize).** Use `aho-corasick` with `MatchKind::LeftmostLongest`, fed the registered
secrets in registration order, giving FR-005/AC-010 (leftmost-longest; length ties by
registration order) directly. Idempotence (FR-006/AC-011) is enforced **referentially**: skip a
region only when it exactly matches a placeholder already minted in the mapping being built for
this call — never by structural sentinel-shape alone, so a coincidental sentinel-shaped span that
contains a registered secret substring cannot suppress that secret's substitution (would violate
AC-003/SC-002).

**Registry API.** A `SecretTokenizer` is constructed from a caller-supplied session salt and an
**order-preserving, first-occurrence-deduplicated** list of secrets (`Vec`-backed, not a
`HashSet` — registration order is load-bearing for FR-005 and reproducibility under NFR-002). It
owns the secret↔placeholder assignment. `tokenize(&self, text) -> (String, Mapping)` returns only
the mapping entries it actually substituted (FR-002). Secret-bearing types (`SecretTokenizer`,
`Mapping`) implement `Debug` manually to redact secret bytes and **do not derive `Serialize`/
`Deserialize`** (AC-015/NFR-005).

## Architecture Diagram

```
caller (session salt + ordered secrets)
        │
        ▼
  SecretTokenizer ──tokenize(text)──▶ (tokenized_text, Mapping)   secret → <<hs:HMAC(salt,secret)>>
        │                                          │
        │                                          ▼  (crosses boundary — later track)
        │                          StreamingDetokenizer(&Mapping)
        │                            push(chunk)/finish()  ◀── ordered chunks
        ▼                                          │
  detokenize(text, &Mapping)  ── wraps ──▶ push+finish ──▶ original text
   (unknown/forged placeholder → verbatim; partial-at-EOF → verbatim; never leaks secret)
```

## Tasks

- [ ] T001 Module scaffold: ASCII placeholder format + `SecretTokenizer` construction (session salt + order-preserving deduped secrets), `HMAC-SHA256(salt, secret)` placeholder minting, redacted `Debug` and no `Serialize` on secret-bearing types (file: crates/honmoon-core/src/secret_tokenizer.rs)
  STOP: if the MAC construction uses the salt as hashed data rather than the MAC key (or a non-keyed hash is substituted), the confused-deputy property fails — stop before anything depends on it.
- [ ] T002 Implement `tokenize` via `aho-corasick` leftmost-longest (ties by registration order), referential idempotence skip, mapping holds only substituted secrets (file: crates/honmoon-core/src/secret_tokenizer.rs) (depends on T001)
  STOP: if leftmost-longest / registration-order tie-break can't be reproduced in a test with the chosen matcher, stop and revisit the matcher.
- [ ] T003 Implement `StreamingDetokenizer` (push/finish): bounded cross-chunk buffer (max placeholder length) with re-scan on invalidated false-start, provenance-bound substitution (mapping placeholders only), fail-safe flush of partial/unknown tokens as verbatim text (file: crates/honmoon-core/src/secret_tokenizer.rs) (depends on T002)
- [ ] T004 Whole-text `detokenize` as a `push`+`finish` wrapper over T003; round-trip + idempotence property tests over an adversarial corpus (file: crates/honmoon-core/src/secret_tokenizer.rs) (depends on T002, T003)
- [ ] T005 Export the module and public API from `honmoon-core` (`pub mod` + `pub use`), add cross-cutting determinism/streaming-equivalence sweep; if the file exceeds the project ~500-LOC convention, split into a `secret_tokenizer/` submodule (`mod.rs` + `streaming.rs` + tests) (file: crates/honmoon-core/src/lib.rs) (depends on T004)

## Dependencies

```
T001 ──▶ T002 ──▶ T003 ──▶ T004 ──▶ T005
                    └────────▲
              (T004 depends on T002 and T003)
```

Linear chain — all tasks touch the same new file, so there is no safe parallelism; T004 joins
the tokenize (T002) and streaming (T003) work.

## Key Files

- `crates/honmoon-core/src/secret_tokenizer.rs` — **new**. The entire primitive (module doc,
  types, tokenize/detokenize/streaming, inline tests). Mirrors `pii.rs` structure, minus serde
  derives on secret-bearing types. Split into a `secret_tokenizer/` submodule dir if it exceeds
  the ~500-LOC convention (T005).
- `crates/honmoon-core/src/lib.rs` — **modify**. Add `pub mod secret_tokenizer;` and a
  `pub use secret_tokenizer::{...}` line beside the existing `pub use pii::{...}`.
- `crates/honmoon-core/Cargo.toml` — **modify**. Add `aho-corasick`, `hmac`, `sha2` as direct
  deps (each already resolved in the workspace lockfile; pin via `[workspace.dependencies]` in
  the root `Cargo.toml` per project convention).
- `crates/honmoon-core/src/pii.rs` — **reference only**. Convention template (module structure,
  UTF-8 handling, inline test style).

## Verification

### Automated Tests

- [ ] `cargo test -p honmoon-core` — all inline `#[cfg(test)]` tests pass (unit + property/corpus
  sweeps for round-trip, streaming-equivalence, and adversarial chunk splits).
- [ ] `cargo llvm-cov -p honmoon-core --fail-under-lines 80` (or the project's coverage tool) —
  new module meets NFR-004's >80% target.
- [ ] `cargo clippy -p honmoon-core --all-targets -- -D warnings` — clean.
- [ ] `cargo fmt --check` — formatted.

### Manual Testing

- `grep` `crates/honmoon-core/Cargo.toml` and the module source to confirm no `tokio`/socket
  import (NFR-001); the added crates (`aho-corasick`/`hmac`/`sha2`) are pure-CPU.
- Eyeball `format!("{:?}", …)` of a populated tokenizer/mapping and `serde_json::to_string` (must
  not compile / must redact) in a scratch test to confirm no secret bytes appear (NFR-005/AC-015).

### Acceptance Criteria Check

Each AC maps to a named test scenario below (AC-001..AC-015). Round-trip (SC-001), no-leak
(SC-002), streaming equivalence (SC-003), no-partial/no-forged-leak (SC-004), and
overlap/idempotence (SC-005) are exercised by the corpus sweeps in T004/T005.

### Observable Outcomes

- A registered secret never appears (in its registered byte form) in `tokenize` output.
- A forged or mutated placeholder in the detokenizer input never yields a secret.
- Streaming and whole-text detokenization produce byte-identical output for any chunk partition.

## Test Scenarios

### T001
- Happy: register 2 secrets with a fixed salt → each gets a placeholder matching the sentinel
  format, within the declared max length.
- Determinism: same salt + same secrets → identical placeholders on repeat construction (AC-009).
- Unforgeability: same secret under two different salts → different placeholders; and a placeholder
  computed with the wrong salt does not match the real one (FR-007).
- Security (Debug): `format!("{:?}", tokenizer)` / `{:?}` of the mapping contain no secret (AC-015).
- Security (Serialize): secret-bearing types do not derive `Serialize` (compile-fail or redacting
  impl asserted) so `serde_json::to_string` cannot emit a secret (AC-015).
- Dedup/order: registering the same secret twice → one placeholder (AC-012); registration order is
  preserved for tie-breaking.
- Zero secrets: constructing with an empty secret set is valid (no panic).

### T002
- Happy: text with one secret → every occurrence replaced; mapping has exactly that entry (AC-001).
- No-leak: tokenized output contains none of the registered secret byte forms (AC-003/SC-002).
- Unused: a registered secret absent from the text → text unchanged, no mapping entry (AC-004).
- Overlap: secret `A` is a substring of secret `AB`; text `AB` → `AB` substituted, not `A` (AC-010).
- Tie: two equal-length secrets matchable at a position → registration order wins (AC-010).
- Idempotence (referential): tokenize(tokenize(x)) does not re-substitute existing placeholders
  (AC-011/FR-006); a coincidental sentinel-shaped span containing a registered-secret substring is
  still substituted (structural-skip regression guard, AC-003).
- Zero secrets: tokenize returns input unchanged with an empty mapping.

### T003
- Happy: a placeholder split across every single boundary → recognized and substituted (AC-005).
- No-partial: while chunks arrive, no prefix of an incomplete placeholder is emitted (AC-006).
- Flush-partial: stream ends mid-placeholder (buffered bytes only a prefix) → emitted verbatim, no
  secret (AC-007/NFR-006).
- False-start: `<<hs:<<hs:{valid}>>` in one buffer window → the real placeholder is still matched
  after the invalidated false start is flushed as literal text.
- Provenance: a placeholder-shaped token absent from the mapping → emitted verbatim (AC-013/FR-008).
- Forgery: a forged/guessed placeholder not in the mapping injected mid-stream → verbatim, no secret
  leaked (AC-014/SC-004).
- Bound: a long run of partial-placeholder-like prefixes that never complete → buffered bytes never
  exceed max placeholder length (NFR-003).
- Empty chunk: `push("")` is a no-op — no panic, no spurious output, buffer state unchanged.

### T004
- Round-trip: `detokenize(tokenize(x)) == x` across the corpus (AC-002/SC-001).
- Equivalence: for every chunk partition, streaming output == whole-text detokenize output (AC-008/SC-003).
- Mutation: a mutated near-match of a real placeholder → left unchanged, no secret (AC-014).

### T005
- Integration: public API reachable from a `honmoon_core::secret_tokenizer::*` import; a
  determinism + streaming-equivalence sweep runs over the corpus green (AC-009/SC-003/SC-005).
- Test expectation: exports and any submodule split are non-behavioral — covered by the sweep
  compiling and running against the public path.

## Progress

_(updated during implementation)_

## Decision Log

- **Stream-first single matcher** — whole-text detokenize wraps the streaming engine, so AC-008
  holds by construction. Alternative (two implementations) rejected as drift-prone.
- **Placeholder = HMAC-SHA256(key=salt, msg=secret)** — resolves FR-007 unforgeability + NFR-002
  determinism together (salt is an explicit key input). Plan review (security P0 / feasibility /
  adversarial) established that `DefaultHasher` cannot satisfy FR-007: its SipHash keys are the
  fixed public constant `(0,0)`, so a salt fed via `Hasher::write()` is hashed *data*, not a MAC
  key — the token would be guessable given the secret. `sha2` is already resolved in the workspace
  lockfile; `hmac` is a small pure-CPU addition, so the earlier "no new dependency" framing is
  dropped as it steered toward the insecure construction.
- **Matcher = aho-corasick LeftmostLongest** — plan review established that the `regex` crate is
  leftmost-**first**, so a naive alternation would silently violate FR-005/AC-010. `aho-corasick`
  (already a transitive dep of `regex`) provides leftmost-longest with registration-order tie-break
  directly.
- **Order-preserving secret store (Vec, first-occurrence dedup)** — registration order is
  load-bearing for FR-005 tie-breaks and NFR-002 reproducibility; a `HashSet`/`BTreeSet` would lose
  it. No new dependency.
- **No `Serialize` on secret-bearing types** — AC-015 covers serialized output; the `pii.rs`
  serde-derive convention is explicitly not applied to `SecretTokenizer`/`Mapping`.

## Surprises & Discoveries

_(updated during implementation)_
