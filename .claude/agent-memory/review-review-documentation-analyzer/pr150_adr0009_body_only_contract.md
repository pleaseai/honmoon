---
name: pr150_adr0009_body_only_contract
description: PR #150 (issue #133) added ADR-0009 + README section stating request inspection covers bodies only; verified fully accurate against mitm.rs/body.rs/signed_body.rs.
metadata:
  type: project
---

PR #150 added `.please/docs/decisions/0009-body-only-inspection-contract.md`, a README
"Wire redaction fail modes" addendum, and an index.md row, documenting that honmoon's request
inspection scans body bytes only — trailers/headers reach upstream unscanned, unredacted, silently
(no warn, no audit, pii.count stays 0).

Verified line-by-line against the implementation:
- The four-branch trailer table (pre/post #130, commit 023cf54) matches `inspect_body` exactly —
  confirmed via `git show 023cf54` diff: branches 1 (`Content-Length <= cap`) and 3 (`None` within
  cap) went from `Full::new` (drops trailers) to `buffered_body` (preserves); branches 2 and 4
  (over-cap) were untouched in both commits, trailers already passed through via `body`/`prefixed_body`.
- The four pre-existing fail-open cases (over-cap, non-UTF-8, undecodable Content-Encoding,
  Content-Range) each do log `tracing::warn!` in `mitm.rs` (lines ~404-441) — README's "loud vs
  silent" distinction is accurate.
- Issues #134, #135, #136 all exist on GitHub and match the ADR's one-line characterizations
  exactly (h2 trailer allowlist gap / stale Trailer header / h2-Content-Length-trailers-dropped-on-h1).
- Tests `trailer_content_is_outside_the_inspection_contract` and
  `the_same_content_in_the_body_is_refused_by_the_same_rule` both exist in
  `crates/honmoon-proxy/tests/redaction.rs` as claimed.
- Module docs on `inspect_body` in mitm.rs and on `buffer_up_to`/`buffered_body` in body.rs do
  state the contract in-code, as the ADR's "recorded in three places" claims.

Only non-finding observation: ADR-0009's Status line ("Accepted (2026-09-11, #133).") deviates in
format from sibling ADRs (0002/0007/0008 just say "Accepted"; 0006 uses "Accepted. Amended
<date> (#N): ..." only for amendments). This is a style variation, not a required-content
violation, so out of scope per the review's "no style/taste" filter — noted here only as a
calibration point for future PRs in this ADR series.

Result: 0 findings. This is a case where the documentation *is* the deliverable and it earned
that — treat as a positive calibration point alongside [[adr_0006_signed_header_amendment]] and
[[pr122_hook_salt_parity]].
