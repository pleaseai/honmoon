---
name: content-length-trailers-h2
description: honmoon-proxy's Content-Length-buffered inspect_body branch can carry trailers via h2 clients, and body.rs's scripted_body helper makes it cheaply unit-testable.
metadata:
  type: project
---

In `crates/honmoon-proxy/src/mitm.rs::inspect_body`, the `Content-Length <= MAX_INSPECT_BODY`
branch calls `body.collect().await` then `collected.trailers().cloned()`. This looks like dead
framing (HTTP/1.1 doesn't allow trailers alongside a declared Content-Length), but mitm.rs has
existing comments elsewhere (`h2 ":authority"` handling) confirming the same handler accepts HTTP/2
client requests, and HTTP/2 *does* permit trailers regardless of Content-Length framing. So this
branch is reachable in production, not just defensive code.

The loopback test harness in `tests/redaction.rs` (`raw_proxy_request`) writes raw HTTP/1.1 wire
bytes only — it cannot exercise this path. But `crates/honmoon-proxy/src/body.rs`'s test module
already has a `scripted_body(frames: Vec<Result<Frame<Bytes>, hudsucker::Error>>) -> Body` helper
that constructs a `Body` from an arbitrary frame sequence, bypassing real wire parsing entirely.
That helper is exactly what's needed for a cheap unit test of this branch: script a data frame
followed by a trailers frame, call `.collect().await`, and assert `collected.trailers()` round-trips
through `buffered_body`. No h2 test harness build-out required.

**Why:** came up reviewing PR #130 (issue #82, trailer-preservation fix) — the PR's own stated
"known gap" claimed this path was untestable due to invalid HTTP/1.1 framing, but that framing
argument doesn't hold for h2 clients, and a cheap unit test route already exists via `scripted_body`.
**How to apply:** when reviewing future honmoon-proxy body/framing changes, check whether a claimed
"HTTP/1.1 makes this unreachable" argument accounts for h2 client support before accepting it as a
reason to skip a test — and reach for `scripted_body` (or an equivalent frame-scripting helper) as
the cheap unit-test escape hatch instead of demanding an h2 e2e harness.
