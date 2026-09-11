---
name: pr146-signed-digest-readme-cli-stale
description: PR #146 (issue #116) fixed BODY_DIGEST_HEADERS being missing from the header-signed decision; ADR-0006 was updated correctly, but README.md wire-redaction section and crates/honmoon-cli/src/main.rs --signed-body help text still only mention framing headers (Content-Length/Content-Encoding/Transfer-Encoding), not digest headers (content-md5/digest/content-digest/repr-digest) — both now stale relative to the fixed code.
metadata:
  type: project
---

PR #146 fixed honmoon-proxy/src/mitm.rs so the signed-header block-or-forward decision asks about
`rewritten_headers()` = REWRITTEN_FRAMING_HEADERS + BODY_DIGEST_HEADERS the request carries (was:
framing headers only). Closes #116 (SigV4 UNSIGNED-PAYLOAD + SignedHeaders=content-md5 had its
signed Content-MD5 stripped with no decision taken).

ADR-0006's Decision section and the removed Consequences bullet were updated correctly and verified
against signed_body.rs/mitm.rs — accurate, no contradictions found.

Two other docs were NOT updated by this diff and are now stale, describing only the framing-header
half of the header-signed decision:
- README.md lines ~207-237 ("Wire redaction fail modes") — says SigV4 UNSIGNED-PAYLOAD uploads are
  "redacted normally" as long as `SignedHeaders` "leaves the framing headers alone", omitting that a
  signed body-digest header (content-md5 etc.) now also triggers the block — this is literally the
  bug #116 fixed, restated as still-true behavior.
- crates/honmoon-cli/src/main.rs ~line 95-111, the `--signed-body` clap doc comment — enumerates
  "(Content-Length, Content-Encoding, Transfer-Encoding — an AWS SDK upload signs content-length
  even under UNSIGNED-PAYLOAD)" as what triggers the header-covers branch, without mentioning digest
  headers.

Pattern: when a "which headers does the header-signed decision cover" fix lands in
honmoon-proxy/src/{mitm,signed_body}.rs, grep README.md and honmoon-cli/src/main.rs for the same
enumerated header list — both keep independent prose copies of it and drift easily. See
[[adr_0006_signed_header_amendment]].
