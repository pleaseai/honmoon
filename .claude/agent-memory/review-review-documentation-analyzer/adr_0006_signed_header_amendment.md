---
name: adr-0006-signed-header-amendment-verified
description: PR #115 amended ADR-0006 to cover header-signed (not just body-signed) requests under wire redaction — verified accurate against signed_body.rs/mitm.rs
metadata:
  type: project
---

Reviewed PR #115 (branch amondnet/issue-83-signed-header-rewrite, issue #83) which extends
ADR-0006 (`.please/docs/decisions/0006-signed-body-requests-under-wire-redaction.md`), README's
"Wire redaction fail modes" section, and the `--signed-body` CLI help text to also cover
requests whose signature covers a *framing header* (`Content-Length`, `Content-Encoding`,
`Transfer-Encoding`) rather than the body itself — the gap the old ADR text explicitly called
out as "Tracked in #83".

Cross-checked every claim (header names, `X-Honmoon-Reason: signed-header-redaction` vs
`signed-body-redaction`, audit rule `wire-redaction/signed-headers` vs `wire-redaction/signed-body`,
default `block`, SigV4/RFC 9421/cavage parsing, "only headers the rewrite actually changes"
via `reframed_headers`) against `crates/honmoon-proxy/src/signed_body.rs` and
`crates/honmoon-proxy/src/mitm.rs` — all accurate, no contradictions found.

**Why worth recording:** this is a rare case of a fully clean, high-quality doc PR in this repo —
useful as a calibration point for what "no issues" actually looks like here, since most reviewed
PRs have at least a minor gap ([[honmoon-crate-table-convention]] pattern).

**How to apply:** the one soft spot found was `.please/docs/decisions/index.md` (auto-maintained by
`/please:plan`, not touched by this diff) still titling ADR-0006 "Body-signed requests under wire
redaction" even though the ADR body now gives equal weight to header-signed requests — flag at low
confidence only, since the index is auto-generated and the diff didn't touch it.

**Second clean PR confirmed (#120, issue #81, 2026-09-11):** amended the same ADR again to narrow
SigV4 body-signature detection (presigned URL / bare `x-amz-content-sha256` no longer count alone
unless a signed-payload marker or 64-hex hash is present). Verified every ADR/README claim
line-by-line against `aws_sigv4_signs_body`/`declares_unsigned_payload`/`declares_signed_payload`/
`sigv4_presigned_query` in `signed_body.rs` and the new `redaction.rs` integration tests — exact
match, including the "operator wants old strictness → use `egress` policy" remediation the issue
required. Issue numbering in prose checked out too: "review of #80 (#81)" means PR #80 introduced
ADR-0006 and its review spawned follow-up issue #81 — not a fabricated cross-reference. This repo's
signed_body.rs/mitm.rs doc comments and ADR-0006 are a reliable place to expect precise, accurate
prose; spend review effort on cross-checking numeric/behavioral claims rather than assuming drift.

**Third clean PR confirmed (#130, issue #82, 2026-09-11):** fixed `--signed-body forward` silently
dropping request trailers (a trailer-carried `Content-Digest` an RFC 9421 signature covers) because
buffered bodies were rebuilt with `http_body_util::Full`, which carries no trailers. Only
`crates/honmoon-proxy/{body.rs,mitm.rs}` and its tests changed — no doc files. Checked ADR-0006's
"`forward` returns the original request untouched — same bytes, same headers", README's "A signed
request with nothing to redact is always forwarded untouched", and the CLI `--signed-body` help's
"forward sends the original bytes unredacted": all three already made this exact claim, and were
technically inaccurate pre-fix for a chunked body with a trailer (which the "untouched" reconstruction
silently dropped) — but the fix makes them accurate rather than stale, so nothing needed updating.
Lesson: when a bugfix closes a gap between an existing "untouched"/"byte-identical" doc claim and
actual behavior, check whether the fix makes the old prose newly true before flagging it as stale.
