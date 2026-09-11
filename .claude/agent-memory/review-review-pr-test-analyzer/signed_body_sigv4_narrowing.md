---
name: signed-body-sigv4-narrowing
description: Why the removed bare_payload_hash_request_keeps_client_accept_encoding test in redaction.rs is not a coverage loss (issue #81 / PR #120) — the narrowing makes Some(AwsSigV4) always imply authentication_signs_headers = true, so the test covered a now-unreachable state
metadata:
  type: project
---

`crates/honmoon-proxy/src/signed_body.rs`'s `aws_sigv4_signs_body` was narrowed
(issue #81): a presigned `X-Amz-Algorithm` query param or a bare
`x-amz-content-sha256` no longer counts as body-signing on its own. Before the
change, a bare hex payload hash alone made `body_signature_scheme` return
`Some(AwsSigV4)` while `authentication_signs_headers` (which requires real
SigV4 auth — an `Authorization` header or a presigned query) was `false`. That
combination was the one case that made the `signature_scheme.is_none()` half
of `mitm.rs`'s identity-negotiation guard (around line 391,
`crates/honmoon-proxy/src/mitm.rs`) non-redundant, and
`bare_payload_hash_request_keeps_client_accept_encoding` in
`crates/honmoon-proxy/tests/redaction.rs` was the test that exercised it.

After the narrowing, `aws_sigv4_signs_body` returning true always implies
`aws_sigv4_authenticates` (hence `authentication_signs_headers`) is also true —
every path to `Some(AwsSigV4)` (header-signed `Authorization`, or presigned
query + a value `declares_signed_payload`) already requires the presigned/auth
evidence that `authentication_signs_headers` checks. So `(Some, false)` is now
unreachable for the AwsSigV4 arm, and deleting that test is not a coverage
loss — it's dropping a test of a state the code can no longer reach. The
`mitm.rs` doc comment at that guard already says as much ("adds nothing today,
but ... if a future scheme breaks that implication"), i.e. the redundancy is
deliberate belt-and-braces, not an oversight.

**How to apply**: if a future PR reviews this guard again, don't flag the
missing `(Some, false)` test unless the code once again makes that combination
reachable (e.g. a new scheme where body-signing doesn't imply header-signing
evidence).
