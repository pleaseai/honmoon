---
name: framing-deliberate-skips
description: How to flag missing-logging bugs inside a code path the task explicitly marks as deliberate/do-not-flag
metadata:
  type: feedback
---

When a review task explicitly says a fallback/skip behavior is deliberate ("do not flag as
a bug"), that immunity covers only the skip-and-forward *behavior itself* — not necessarily
every property of that path. Check whether the task's own description of the deliberate
design also asserts a sub-property (e.g. "skips are logged at debug level") and verify the
code actually satisfies it. A gap between the stated design intent and the implementation is
still a legitimate, flaggable finding — frame it precisely as "the skip is correct and
intended; what's missing is X" so it doesn't read as flagging the excluded behavior.

**Why:** Confirmed via advisor() on `crates/honmoon-proxy/src/mitm.rs`
(`decode_for_inspection`/`inflate_capped`, branch honmoon
`12-review-discussion-decompress-content-encoding-bodies-before-pii-inspection-mitmrs`).
Task said "unsupported/corrupt encodings SKIP the scan ... skips are logged at debug level."
The `Some(other)` unsupported-encoding branch logs via `tracing::debug!`; the gzip/deflate
decode-failure branches (`inflate_capped`'s `Err(_) => None` at the io level, consumed
silently by `decode_for_inspection`) do not log anything. The skip itself is correct
(detect-only, never block traffic) — the finding is the missing debug log, which leaves an
operator asking "why wasn't PII caught here" with zero signal, indistinguishable from a
clean pass-through.

**How to apply:** Before writing off a code path as "excluded by the task's design intent,"
re-read the intent statement for embedded sub-guarantees (logging, error context, cap
behavior, etc.) and check each one against the actual code, not just the top-level behavior.
Also prefer citing the deepest swallow point (here, `inflate_capped`'s `Err(_) => None`,
which discards the underlying `io::Error` with the real failure cause — bad magic / checksum
/ truncation) as the root cause, with call sites as propagation points, rather than only
citing the outer function.
