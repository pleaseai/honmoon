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
not found" for a plan-native task ID (e.g. `T003`, `T004`) when no
`TaskCreate` had registered that ID in the current session's task list —
this is expected when the orchestrator dispatches by plan task ID without
pre-seeding the task-tracking tool. Not an error to retry; just proceed with
the RED-GREEN-REFACTOR work and skip `TaskUpdate` calls that 404, relying on
the plan's `## Progress` section (see [[honmoon-plan-living-document]]) as
the durable completion record instead.

**T005 (final task of this track)**: exporting a module's public API and
splitting an oversized file are best done as one structural pass, verified
by an *external* integration test (`tests/foo_public_api.rs`, its own
compilation unit) rather than another inline `#[cfg(test)]` module — an
inline test can still see private/internal paths even without the `pub use`,
so it can't prove the crate-root re-export is what makes the surface
reachable. Wrote that integration test first (RED: `error[E0432]: unresolved
imports honmoon_core::...`) before adding the `pub use` line, confirming the
re-export was the fix, not a coincidence.

**Splitting an oversized single-file module** (937 lines here, over the
project's ~500-LOC convention): converting `foo.rs` → `foo/mod.rs` +
`foo/submodule.rs` is *pure structural* work — `git mv`/recreate plus a
`pub mod submodule; pub use submodule::{...};` line in `mod.rs` preserves
every external and `#[cfg(test)]` path. Used `sed -n '<start>,<end>p' src >
dest` to extract exact line ranges into the new files instead of hand
retyping — for large or test-heavy files this avoids transcription slips
that a full-file rewrite risks, and `cargo test` immediately proves nothing
was dropped (all 26 prior module tests still passed post-split, same names,
now nested one level deeper as `secret_tokenizer::tests::*` and
`secret_tokenizer::streaming::tests::*`).

**Isolating an orchestrator-owned hunk already sitting in the working tree**:
mid-track, `plan.md`'s `## Tasks` section had an uncommitted checkbox flip
(T004 `[ ]`→`[x]`) left over from a prior session/process — not something
this task's `Files:` scope covered, and `## Tasks` is explicitly
orchestrator-owned. Hand-crafting a patch with `git apply --cached` and
copied `@@` hunk headers is fragile (line-number drift after an edit already
landed causes "corrupt patch" errors); `printf 'n\ny\n' | git add -p <file>`
interactively answering per-hunk (`n` to skip the foreign hunk, `y` to stage
only mine) is the reliable way to commit just the `## Progress` addition
while leaving the pre-existing foreign edit untouched and uncommitted in the
tree, exactly as found.

**T004 confirmed the wrapper design holds in practice**: `detokenize(text,
&Mapping)` is a literal `push(text)` + `finish()` two-liner over
`StreamingDetokenizer` — no independent matching logic needed. The property
test worth reusing on similar streaming-vs-whole-text primitives: build a
small adversarial corpus (secret at start/mid/end/adjacent-no-separator,
repeated, overlapping/substring like `"A"`/`"AB"`, regex-special chars,
sentinel-shaped-but-literal secret text, multi-byte UTF-8 neighbors, empty
input, no-match input), then for each corpus case enumerate every
char-boundary single-split point of the *tokenized* text (not just a
sampled few) plus a couple of 3-/4-way splits, feed each partition through a
fresh `StreamingDetokenizer`, and assert byte-equality against the
whole-text wrapper's output. This exercises hundreds of boundary partitions
per corpus case for free and is the actual anti-drift proof for AC-008/
SC-003 — a handful of hand-picked split points is not equivalent.
