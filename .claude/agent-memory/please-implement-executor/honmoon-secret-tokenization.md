---
name: honmoon-secret-tokenization
description: Streaming reverse-substitution boundary-safety design used in honmoon-core's secret_tokenizer.rs, and a TaskUpdate tool quirk observed on this track.
metadata:
  type: project
---

Honmoon (`crates/honmoon-core/src/secret_tokenizer.rs`) implements a streaming
placeholder→secret detokenizer (`StreamingDetokenizer`, track
`secret-tokenization-20260707`, T003) as a single `push`/`finish` state
machine so whole-text `detokenize` (T004) can wrap it without a second,
drift-prone implementation.

**Reusable design pattern**: when a delimiter-bounded token format (fixed
ASCII prefix + fixed-width body + fixed ASCII suffix) must be recognized
across streamed chunks with a bounded cross-chunk buffer, one mechanism
handles three requirements at once — "flush exactly one literal byte from
the start of an invalidated candidate window, then re-scan the whole
remaining buffer from scratch for the next delimiter occurrence." This single
step correctly:
1. re-discovers a genuine token that starts partway through a false-start
   window (e.g. `<<hs:<<hs:{valid}>>` — a delimiter immediately followed by
   another delimiter run),
2. cascades an unknown/forged-but-shaped token out as literal bytes when no
   real token turns out to be inside it, and
3. never grows the buffer past the fixed maximum width, because a byte is
   only ever retained pending more input when the buffered run is strictly
   shorter than the max width.
Do not implement false-start re-scan and unknown-token-verbatim as two
separate code paths — they collapse into the same one-byte-flush-and-rescan
loop.

**Boundary-safety gotcha**: when the token body may contain arbitrary
attacker-controlled UTF-8 (not guaranteed ASCII), slicing the buffer at
`start + fixed_width` can panic (not a char boundary) even though the
delimiters themselves are ASCII. Guard with `buffer.is_char_boundary(offset)`
before slicing, and treat a non-boundary offset as "not a real token" (fail
closed) rather than trying to recover — a real token in this design is
provably all-ASCII, so a non-boundary offset can never be one anyway.

**Why**: this came up because `honmoon-core` must stay transport-agnostic
and the streaming detokenizer's buffer bound (NFR-003) has to hold under
hostile/never-completing input while still catching genuine tokens hidden
inside false starts — a subtlety the plan's Architecture Decision flagged
explicitly ("a single linear tail-position counter is insufficient").

**How to apply**: reach for this pattern any time a future honmoon-core (or
similar) task needs a bounded streaming matcher for a fixed-format sentinel
token (delimiters + fixed body length) over arbitrary UTF-8 input.

---

**Tool quirk observed**: on this track, the `TaskUpdate` tool returned "Task
not found" for a plan-native task ID (e.g. `T003`) when no `TaskCreate` had
registered that ID in the current session's task list — this is expected
when the orchestrator dispatches by plan task ID without pre-seeding the
task-tracking tool. Not an error to retry; just proceed with the
RED-GREEN-REFACTOR work and skip `TaskUpdate` calls that 404, relying on the
plan's `## Progress` section (see [[honmoon-plan-living-document]]) as the
durable completion record instead.
