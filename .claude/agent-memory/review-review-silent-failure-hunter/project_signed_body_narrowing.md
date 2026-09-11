---
name: project-signed-body-narrowing
description: signed_body.rs aws_sigv4_signs_body narrowing (issue #81 / PR #120) reviewed clean — no silent-failure defects found
metadata:
  type: project
---

Reviewed PR #120 narrowing `aws_sigv4_signs_body` in
`crates/honmoon-proxy/src/signed_body.rs` (header-signed SigV4 now requires
payload not opted out via `UNSIGNED-PAYLOAD`/`STREAMING-UNSIGNED-PAYLOAD…`;
presigned SigV4 now additionally requires `declares_signed_payload` — a 64-hex
`x-amz-content-sha256` or a `STREAMING-AWS4-` marker — via new helpers
`declares_unsigned_payload`, `declares_signed_payload`, `sigv4_presigned_query`).

Traced every branch by hand against the pre-diff logic (old
`aws_sigv4_authenticates(...) || hex_payload_hash` with no length check) and
found the new code strictly narrows toward the *restrictive* direction (more
requests get redacted rather than forwarded-as-signed) — the direction that
cannot leak secrets. No permissive-fallthrough regression, no new
non-UTF8/whitespace/duplicate-header issue introduced (the `header_str`
single-value read for `x-amz-content-sha256` and `Authorization` both predate
this diff and are unchanged call sites). `mitm.rs`'s comment-only change
("`signature_scheme` adds nothing today because every body-signing scheme
implies header-signing evidence") checked true against the current
(unchanged) `message_signature_*`/`cavage_*` predicates.

**Why:** issue #81 asked specifically to check for silent fallthrough to the
permissive classification on malformed input — worth recording that this PR
was scrutinized closely and cleared, so a future re-review of the same commit
doesn't redo the full branch trace.

**How to apply:** if a later PR touches `aws_sigv4_signs_body` again, diff
against this narrowed version (not the original pre-#81 version) and recheck
the same branch matrix: unsigned-payload marker, header-signed only, presigned
+ signed marker, presigned + no marker, presigned + short/invalid hex.
