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

**Result: 0 findings — and that verdict was wrong.** Do not treat this as a positive calibration
point; it is the opposite. After this pass, codex, greptile and cubic found three *false absolute
claims* in the same text I had just verified:

1. "header and trailer values are forwarded verbatim" — false on the redaction-rewrite path:
   `forwarded_request` rebuilds the body with `Full::new`, which carries no trailer frame, so a
   redacted request *drops* its trailers.
2. "Nothing in the pipeline reads a `HeaderMap`" — false: `inspect_body` reads `Content-Length`,
   `Content-Type` and `Content-Encoding`, and signature detection reads `Authorization`. The true
   claim is that no *detector* runs over a header map.
3. "`pii.count` stays 0, so no `pii.*` rule can fire, no audit record" — false: `eval_program`
   binds `pii` with its empty default so absence conditions work, so `pii.count == 0` fires and a
   matching deny audits. Only *positive-finding* rules cannot fire.

**What I did wrong:** I verified the ADR's *argument* (the four-branch table, the parity reasoning,
the #130 history) and confirmed its citations resolve, then read the contract's own clauses as
framing rather than as claims. The argument was sound; the clauses were what shipped.

**How to apply:** in a docs PR, the load-bearing sentences are the unconditional ones —
"never", "nothing", "always", "verbatim", "no X can happen". Enumerate every absolute claim and
check each against source *individually*, before assessing whether the surrounding argument holds.
A correct argument wrapped around a false guarantee is the failure mode of this PR class, and it is
invisible if you only follow the reasoning. Contrast with [[adr_0006_signed_header_amendment]] and
[[pr122_hook_salt_parity]], which were genuinely clean.

**Two more classes surfaced in later rounds, neither an absolute claim.** Add both to the checklist:

4. *An enumeration drifting from the list it claims to summarize.* A paragraph opened "the four
   fail-open cases above" and then enumerated a different four — `Content-Range` silently swapped
   for a decode-overflow case that was not on the original list. Re-read what "the N above"
   actually names; do not trust the count.
5. *A fail-open list read as a list of uninspectable requests.* Two of honmoon's four fail-opens
   are **redaction-only**: detection runs at `mitm.rs:702-703` and `decide_explained` at
   `mitm.rs:727`, both inside `inspect_body` and both before `forwarded_request`, whose
   `CONTENT_RANGE` check (`mitm.rs:403`) skips only the rewrite. So a `Content-Range` partial
   upload is scanned like any other body, and a body with an undecodable `Content-Encoding` reaches
   the scanner as raw bytes — though that fallback only catches mislabelled plaintext, since
   genuinely compressed bytes still fail `utf8_prefix` and yield nothing. Reaching the scanner is
   not the same as being inspectable; keep the two apart. When a doc groups cases by their *warn*,
   check whether they share the behaviour the grouping implies.

Also worth noting for prose review generally: "no `warn` is logged for header-shaped fields" was
*true as meant* and still had to be qualified, because two of the four warns are **triggered** by a
header (`Content-Range` presence, an unparseable `Content-Encoding`) even though each reports a
skipped *body* rewrite. A claim that survives verification can still contradict what an operator
reads. Same lesson shape as [[guard-unnecessary-doc-comment]].
