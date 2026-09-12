---
name: honmoon-proxy-forwarded-blocked-variant
description: "honmoon-proxy internal enums sometimes borrow a too-wide hudsucker sum type for one variant; mitm.rs's `Forwarded::Blocked` did and was narrowed to `Response<Body>` in PR 180 — check new internal enums for the same shape, not this one"
metadata:
  type: project
---

`crates/honmoon-proxy/src/mitm.rs` defines a module-private `Forwarded` enum modelling "did wire
redaction forward, rewrite, or locally answer this request". Its `Blocked` variant originally held
hudsucker's `RequestOrResponse`, which is itself `{ Request(Request<Body>), Response(Response<Body>) }`
— so `Blocked` could structurally hold a *request*, and `forwarded_request`'s match arm would have
handed it back to hudsucker as "keep forwarding this", silently defeating the block. Only the two
constructors kept that from happening; the compiler did not.

**Status: fixed in PR 180.** `Blocked` now holds `Response<Body>`, `signed_body_response` and
`signed_headers_response` return `Response<Body>`, and the single match arm does the `.into()`.
Do not re-flag this variant — it is already narrow.

**Why:** the durable part is the *pattern*, not this instance. An internal enum reaching for a
library sum type (`RequestOrResponse` and friends) "for the convenience of `.into()`" buys a
variant that admits states the code never intends, and the invariant then lives in the call sites
instead of the type.

**How to apply:** when reviewing a new module-private enum in `honmoon-proxy` that wraps a
hudsucker or hyper sum type for only one of its cases, check whether the single variant actually
needed was available and skipped. Same family as [[honmoon-proxy-sync-point-tracking]]'s
encapsulation gap: an invariant true by construction today that the type does not enforce.
