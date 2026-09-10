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
