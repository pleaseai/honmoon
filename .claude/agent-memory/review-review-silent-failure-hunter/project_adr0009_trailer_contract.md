---
name: adr0009-trailer-contract
description: PR #150 (ADR-0009) documents the body-only inspection contract for request trailers/headers — the warn claims, the debug-vs-warn split and buffered-vs-overflow trailer visibility all verified accurate against source
metadata:
  type: project
---

PR #150 documents (no behavior change) that honmoon's request inspection scans
body bytes only, so trailer/header content fails open without a `warn`, and
contrasts it with four genuinely loud
fail-open cases in the wire-redaction rewrite path (`crates/honmoon-proxy/src/mitm.rs`
~L400-441: over-cap, undecodable Content-Encoding, non-UTF-8, Content-Range —
each does call `tracing::warn!`).

Verified on 2026-09-11:
- The four README "fail modes" warns are real and unconditional (given
  `--redact-secrets` is on) — checked each call site in
  `HonmoonHandler::forwarded_request`, the fn after
  `let Some(redaction) = &self.state.redaction`. (There is no `apply_redaction`
  in this crate; an earlier version of this note guessed that name.)
- There ARE `tracing::debug!` calls for `StrictDecode::Overflow`/`Unavailable`
  in `mitm.rs` (~L676-684) and in `body.rs` `decode_for_inspection`/
  `decode_for_redaction`, but those are for the separate *PII-detection* decode
  step, and the body.rs ones are `#[cfg(test)]`-only (dead in prod) — neither
  contradicts the README's warn claims about the *redaction rewrite* path.
- A "warn on trailers present" is only reachable on the two buffered branches
  of `inspect_body` **when driven by an observed trailer frame**:
  `buffer_up_to`'s `Overflow` arm never parses trailers (`rest` stays unread),
  and the `Some(len) > MAX_INSPECT_BODY` arm forwards `body` raw. But a warn
  driven by the request's `Trailer:` *declaration header* has no such limit —
  headers are parsed before the `content_length` match and `parts` survives it.
  The ADR was corrected on this during review: the real reason to reject that
  warn is that `Trailer:` is advisory and routinely omitted, so the adversary
  switches it off while ordinary gRPC traffic still trips it.
- Pinning tests in `crates/honmoon-proxy/tests/redaction.rs`:
  `trailer_content_is_outside_the_inspection_contract` (+ its body control),
  `a_redacted_body_drops_the_request_trailer` (the rewrite exception), and
  `an_absence_rule_still_matches_a_request_whose_trailer_carries_a_secret`.

**Correction to this note's original verdict (no findings).** Doc-only work
should be judged on accuracy against source — and on that standard the first
draft did *not* hold up. Later reviewers found three absolute claims that were
false: "forwarded verbatim" (the redaction rewrite drops trailers), "nothing in
the pipeline reads a `HeaderMap`" (`inspect_body` reads Content-Length/Type/
Encoding), and "no `pii.*` rule can fire, no audit record" (absence rules fire
and audit). **Absolute claims in prose are the ones to check first** — my pass
verified the argument and skipped the contract's own clauses.
See [[feedback_framing_deliberate_skips]] for the general caution that applies
when a PR frames something as "not a bug."
