---
name: pr208-relay-write-half-claims
description: 'PR #208 (issue #121, relay owns the client write half) doc-comment audit in crates/honmoon-proxy/src/runtime/postgres.rs — three imprecisions found and all three fixed in that PR (a field-name conflation, a false absolute, and a claim true only via a third mechanism); the shapes are what to re-check, not the text'
metadata:
  type: project
---

PR #208 rewrote `postgres.rs` so the upstream→client relay owns the client
`OwnedWriteHalf` outright (no `Arc<Mutex<..>>`, no `watch`, no `Delivered`,
`RelayEnd`, `can_inject`, `debt`). Reviewed every doc comment as a falsifiable claim. Three held up, and **all three
were corrected in PR #208 before merge** (commit `13c020d`) — so do not go looking
for the text below in the file. What is worth keeping is the shape of each, because
each is a different way this file's comments drift:

- **`ClientLink::refusal()`'s doc conflates `Forwarded::flushes` with
  `Forwarded::flushes_covered`.** The comment says the flush count it reads
  "is exactly the snapshot the most recent forwarded sync point left" — that
  description matches `flushes_covered` (updated only in
  `forwarded_sync_point()`), but the code actually loads the live running
  `flushes` counter, which keeps incrementing after the last `Sync`. The
  mechanics are still correct (the same live `flushes` value is what
  `flush_drained`'s `owed` parameter reads too, so the comparison in
  `Relay::releasable` is self-consistent) — this was a wrong description of
  which field is read, not a bug. Two fields with adjacent, similarly-worded
  doc comments and a shared vocabulary word ("coverage") is exactly the kind
  of place a conflation like this survives review. **The shape to re-check:**
  when two counters differ only by when they are sampled, read the `load(..)`
  line rather than the sentence above it.
- **`Stop::Client`'s "the copy fails mid-payload by definition" is a false
  absolute.** `copy_exact` does `src.read_exact` then `dst.write_all` per
  chunk; a failure on the very first chunk's read (upstream drops before any
  bytes arrive) means zero payload bytes ever reached the client — not
  "mid-payload". The broader `Stop::Client` enum doc one level up already
  hedges correctly ("payload never arrived", not "some of the payload"); only
  the narrower call-site comment overclaimed. Low real-world stakes (the
  `Stop::Client` handling is identical either way) but a clean falsify-the-
  absolute catch. **The shape to re-check:** a comment about a loop's failure
  mode has to hold for the loop's *first* iteration too.
- **The `flushes_covered`/#153 "sync side still holds the barrier" claim is
  true, but for a narrower reason than the comment states, and I initially
  thought it was false.** I built a counterexample (two `Sync`s in flight
  around a queued refusal) that looked like it would let a stale
  `flushes_covered` snapshot release a refusal before the sync side is
  satisfied. It doesn't, because `ClientLink::inject`'s one-slot channel +
  awaited `oneshot` ack freezes the *entire* message loop — no further frame
  of any kind can be forwarded — for as long as an answer is queued, so no
  second `Sync` can ever land while a refusal is pending. This exact
  resolution is already recorded, as verified, in
  `.claude/agent-memory/review-review-security-reviewer/postgres-refusal-ordering-barrier.md`'s
  "Verified once against the #121 shape, so do not re-derive" section — read
  that file before re-deriving this on a future PR. Lesson: a "cannot happen
  because the other side of the AND already blocks it" comment can be true
  only because of a *third*, separately documented mechanism (here: the
  injection freeze) — trace the cross-reference before either accepting or
  flagging the local claim in isolation. The comment now cites the freeze
  directly, so the next reader does not have to rebuild the counterexample.
- **`NoData` (`n`) missing from the "can never end a batch" tag enumeration
  is already honestly tracked as #211, in the comment itself** (three
  separate mentions, confirmed present at the current HEAD) and mirrored in
  the ADR-0007 rewrite. Do not re-report this — it looked like an
  undocumented gap on a fast read of a truncated shell excerpt, but a full
  read of the surrounding paragraph shows it is explicitly named.

Related: [[postgres_sync_point_protocol_claims]], [[postgres_flush_barrier_pr147]].
