---
name: rewritten-headers-generic-dispatch
description: In mitm.rs's signed-headers block-or-forward decision, the Forward/Block match arms are content-agnostic over which header names are in `broken` — so per-header-name integration tests add little marginal safety once one instance of each mode is covered.
metadata:
  type: project
---

`crates/honmoon-proxy/src/mitm.rs`'s header-signed decision (around the
`rewritten_headers`/`signed_headers_among`/`broken` block, issue #116) branches
only on whether `broken` is empty, and the `Forward`/`Block` match arms never
inspect which header names are in it — the arms are identical whether `broken`
contains a framing header (`content-length`) or a body-digest header
(`content-md5`, `digest`, `content-digest`, `repr-digest`).

Likewise `signed_headers_among`/`header_is_signed`/`sigv4_signs_header` in
`crates/honmoon-proxy/src/signed_body.rs` do a case-insensitive string-list
membership check with no per-name special-casing — so testing one
`BODY_DIGEST_HEADERS` member at the integration level (e.g. `content-md5`)
provides most of the coverage value; the other three are low-marginal-risk
gaps, not real ones, unless the unit-level exhaustive test over
`BODY_DIGEST_HEADERS` (`carried_body_digest_headers_join_the_reframed_ones`)
is ever removed.

**Why:** avoids over-flagging "test the other N enum/constant variants too"
suggestions in this specific dispatch as high-severity when the dispatch code
provably doesn't branch on the variant.

**How to apply:** when reviewing tests touching this decision point (or
sibling dispatches built the same way — checkable via `sed -n` on the match
arms), rate missing per-variant integration tests low severity/confidence if
an exhaustive unit test over the enum/constant array already exists nearby,
and the dispatch code itself is generic over the values in the array.
