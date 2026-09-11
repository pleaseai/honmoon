---
name: adr0009-trailer-contract
description: PR #150 (ADR-0009) documents the body-only inspection contract for request trailers/headers — verified accurate against source
metadata:
  type: project
---

PR #150 documents (no behavior change) that honmoon's request inspection scans
body bytes only, so trailer/header content silently fails open (no `warn`, no
audit, `pii.count` stays 0), and contrasts it with four genuinely loud
fail-open cases in the wire-redaction rewrite path (`crates/honmoon-proxy/src/mitm.rs`
~L400-441: over-cap, undecodable Content-Encoding, non-UTF-8, Content-Range —
each does call `tracing::warn!`).

Verified on 2026-09-11:
- The four README "fail modes" warns are real and unconditional (given
  `--redact-secrets` is on) — checked each call site in `apply_redaction`
  (name TBD, the fn after `let Some(redaction) = &self.state.redaction`).
- There ARE `tracing::debug!` calls for `StrictDecode::Overflow`/`Unavailable`
  in `mitm.rs` (~L676-684) and in `body.rs` `decode_for_inspection`/
  `decode_for_redaction`, but those are for the separate *PII-detection* decode
  step, and the body.rs ones are `#[cfg(test)]`-only (dead in prod) — neither
  contradicts the README's warn claims about the *redaction rewrite* path.
- The ADR's claim that a hypothetical "warn on trailers present" would only be
  reachable on the two buffered branches of `inspect_body` (Content-Length
  <= cap, and unknown-length within cap) and silently absent on the two
  over-cap branches is correct: `buffer_up_to`'s `Overflow` arm never parses
  trailers (`rest` stays unread), and the `Some(len) > MAX_INSPECT_BODY` arm
  forwards `body` raw without touching it at all.
- Pinning tests `trailer_content_is_outside_the_inspection_contract` and
  `the_same_content_in_the_body_is_refused_by_the_same_rule` in
  `crates/honmoon-proxy/tests/redaction.rs` pass and correctly demonstrate the
  documented boundary.

No findings — this is a case where doc-only work should be judged on accuracy
against source rather than assumed correct; it held up under verification.
See [[feedback_framing_deliberate_skips]] for the general caution that applies
when a PR frames something as "not a bug."
