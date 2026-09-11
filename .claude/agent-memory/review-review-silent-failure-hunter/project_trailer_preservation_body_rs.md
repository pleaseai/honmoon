---
name: project-trailer-preservation-body-rs
description: 'PR #130 (issue #82) trailer-preservation review in body.rs/mitm.rs — two low-risk edge cases to recheck if this code is touched again: a dead-code frame-kind drop, and HeaderMap::extend overwriting rather than merging'
metadata:
  type: project
---

`buffer_up_to`'s `Err(frame) => if let Ok(more) = frame.into_trailers() { ... }` silently
drops any frame that is neither data nor trailers, with no logging. Verified against
`http-body` 1.1.0 (`~/.cargo/registry/.../http-body-1.1.0/src/frame.rs`) that `Frame`'s
`Kind` enum currently only has `Data`/`Trailers` variants, so the branch is dead code
today — low real risk, but it would silently regress the trailer-preservation guarantee
this PR exists to deliver if a third frame kind is ever added upstream.

Also: `HeaderMap::extend(other)` (used to merge multiple trailer frames in the same
function) **overwrites** duplicate keys with the incoming map's value rather than
appending — confirmed via the doctest in `http` crate's `map.rs` (`map["host"] ==
"foo.bar"` after extending a map that already had `host` set). If a client ever sends
its digest trailer split across more than one `Frame::trailers()` call with overlapping
header names, the earlier value is silently lost. Unlikely in practice (bodies normally
emit at most one trailers frame) — recorded here so a future pass doesn't have to
re-derive it.

**How to apply:** if `body.rs`'s `buffer_up_to`/trailer handling is touched again, recheck
whether these edge cases became reachable (e.g. a `http-body` major bump, or hudsucker
changing how it splits trailer frames). See also [[project_signed_body_narrowing]].
