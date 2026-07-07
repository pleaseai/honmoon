//! Streaming and whole-text reverse substitution (placeholder → secret).
//!
//! Split out of `secret_tokenizer` (T005) purely for file-size hygiene; the
//! public API (`StreamingDetokenizer`, `detokenize`) is re-exported from the
//! parent module unchanged.

use super::{MAX_PLACEHOLDER_LEN, Mapping, PLACEHOLDER_PREFIX};

/// A streaming reverse-substitution engine (FR-004): accepts ordered chunks
/// of placeholder-bearing text and emits detokenized output, buffering only
/// the bounded trailing fragment needed to recognize a placeholder split
/// across a chunk boundary (AC-005).
///
/// Provenance-bound (FR-008/AC-013): only placeholders present in the
/// `Mapping` supplied at construction are substituted; anything else that is
/// placeholder-shaped — unknown, forged, or a mutated near-match — passes
/// through verbatim (AC-013/AC-014/SC-004). Fail-safe (NFR-006): while
/// chunks are still arriving, no prefix of an incomplete placeholder is ever
/// emitted as final output (AC-006); on `finish`, a buffered-but-never-
/// completed placeholder fragment is emitted verbatim, never a secret
/// (AC-007).
///
/// `detokenize` (T004) is implemented as `push(text)` + `finish()` over this
/// same engine, so whole-text and streaming detokenization can never drift
/// apart from one another (AC-008 by construction) — this is the only
/// reverse-substitution state machine in the module.
pub struct StreamingDetokenizer<'a> {
    mapping: &'a Mapping,
    /// Bytes not yet safely emitted. Bounded to under `MAX_PLACEHOLDER_LEN`
    /// bytes whenever more chunks may still arrive (NFR-003): any run at
    /// least that long has already been resolved — matched, invalidated, or
    /// flushed — by `drain` before `push`/`finish` returns.
    buffer: String,
}

/// One scan-loop iteration's outcome in [`StreamingDetokenizer::drain`].
enum Step {
    /// Keep scanning from this new (char-boundary) buffer index.
    Advance(usize),
    /// Stop; retain `self.buffer[keep_from..]` as the undecidable remainder.
    Stop(usize),
}

impl<'a> StreamingDetokenizer<'a> {
    /// Begin a streaming detokenization bound to `mapping`: only
    /// placeholders `mapping` actually holds will ever be substituted
    /// (FR-008).
    pub fn new(mapping: &'a Mapping) -> Self {
        Self {
            mapping,
            buffer: String::new(),
        }
    }

    /// Current byte length of the cross-chunk buffer. Exposed only to this
    /// module's tests, to assert the NFR-003 bound directly.
    #[cfg(test)]
    fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Accept the next chunk (in stream order) and return whatever output
    /// is safe to emit now. An empty chunk is a no-op.
    pub fn push(&mut self, chunk: &str) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        self.buffer.push_str(chunk);
        self.drain(false)
    }

    /// Finalize the stream: flush all buffered bytes. A remaining fragment
    /// that never completed into a placeholder is emitted verbatim as
    /// literal text — never as a secret (AC-007/NFR-006).
    pub fn finish(mut self) -> String {
        self.drain(true)
    }

    /// Resolve as much of `self.buffer` as is currently decidable, moving
    /// resolved bytes into the returned output. Unless `is_final`, an
    /// undecidable bounded remainder (a fragment that might still grow into
    /// a placeholder) is left in `self.buffer` rather than emitted.
    fn drain(&mut self, is_final: bool) -> String {
        let mut output = String::new();
        let mut i = 0;
        // Scan by index and compact once at the end. A front `drain(..1)` per
        // step memmoves the whole tail (O(len)), so the one-byte false-start
        // rescan was O(len^2) on adversarial input (a large chunk densely
        // packed with `<<hs:` false starts); index scanning keeps it linear.
        // `i` only ever lands on a char boundary (it advances by a prefix
        // match offset, by one ASCII byte of `PLACEHOLDER_PREFIX`, or by a
        // boundary-checked `MAX_PLACEHOLDER_LEN`). See `resolve_at_prefix`.
        let keep_from = loop {
            let Some(rel) = self.buffer[i..].find(PLACEHOLDER_PREFIX) else {
                break self.flush_no_prefix(i, is_final, &mut output);
            };
            // Everything before the leftmost prefix can never be part of a
            // placeholder, so it is always safe to emit now.
            output.push_str(&self.buffer[i..i + rel]);
            i += rel;
            match self.resolve_at_prefix(i, is_final, &mut output) {
                Step::Advance(next) => i = next,
                Step::Stop(keep_from) => break keep_from,
            }
        };

        // Single compaction: drop everything resolved into `output`, keeping
        // only the undecidable remainder (≤ MAX_PLACEHOLDER_LEN-1 bytes when
        // more input may still arrive; empty when finalized).
        self.buffer.drain(..keep_from);
        output
    }

    /// No `PLACEHOLDER_PREFIX` remains at or after `i`: emit everything except
    /// a trailing fragment that could still grow into a `PLACEHOLDER_PREFIX`
    /// with more input (nothing when finalizing). Returns the retained
    /// remainder's start index.
    fn flush_no_prefix(&self, i: usize, is_final: bool, output: &mut String) -> usize {
        let keep = if is_final {
            0
        } else {
            partial_prefix_suffix_len(&self.buffer[i..])
        };
        let flush_to = self.buffer.len() - keep;
        output.push_str(&self.buffer[i..flush_to]);
        flush_to
    }

    /// Resolve the window at `i`, which begins with `PLACEHOLDER_PREFIX`.
    /// Appends resolved bytes to `output` and returns how the scan proceeds.
    fn resolve_at_prefix(&self, i: usize, is_final: bool, output: &mut String) -> Step {
        let remaining = self.buffer.len() - i;
        let has_full_candidate = remaining >= MAX_PLACEHOLDER_LEN
            && self.buffer.is_char_boundary(i + MAX_PLACEHOLDER_LEN);

        if has_full_candidate {
            let candidate = &self.buffer[i..i + MAX_PLACEHOLDER_LEN];
            if let Some(secret) = self.mapping.get(candidate) {
                output.push_str(secret);
                return Step::Advance(i + MAX_PLACEHOLDER_LEN);
            }
            // A false start: `PLACEHOLDER_PREFIX` matched here, but the full
            // candidate window is not a placeholder this session minted —
            // unknown/forged (AC-013/AC-014), or another delimiter run
            // beginning inside this window (e.g. `<<hs:<<hs:{valid}>>`). Emit
            // exactly the leading byte as literal text — always a lone ASCII
            // byte of `PLACEHOLDER_PREFIX`, hence a valid char boundary — and
            // re-scan, so a genuine placeholder start later in this window is
            // still found (Architecture Decision: false-start re-scan).
            output.push_str(&self.buffer[i..i + 1]);
            return Step::Advance(i + 1);
        }

        if remaining >= MAX_PLACEHOLDER_LEN {
            // There ARE at least MAX_PLACEHOLDER_LEN bytes, but the window
            // straddles a non-ASCII character at its end — a real placeholder
            // is pure ASCII, so this window can never resolve into one. Do NOT
            // flush the whole buffer (a genuine placeholder may follow later
            // in it): emit one leading byte and re-scan, like the false start.
            output.push_str(&self.buffer[i..i + 1]);
            return Step::Advance(i + 1);
        }

        if !is_final {
            // Fewer than a full window buffered and more may still arrive:
            // hold it back, already bounded to under MAX_PLACEHOLDER_LEN bytes
            // (AC-006/NFR-003).
            return Step::Stop(i);
        }
        // Finalized mid-placeholder: no full placeholder can hide in a
        // sub-`MAX_PLACEHOLDER_LEN` tail, so fail closed and emit the
        // remainder verbatim, never a secret (AC-007).
        output.push_str(&self.buffer[i..]);
        Step::Stop(self.buffer.len())
    }
}

/// Whole-text detokenization (FR-003): reconstruct the original text from
/// `text` (placeholder-bearing) and the `mapping` produced for it.
///
/// This is a thin wrapper over `StreamingDetokenizer` — `push(text)` then
/// `finish()` — rather than a second, independently written matching
/// implementation, so whole-text and streaming detokenization share one
/// engine and can never drift apart from each other (AC-008 by
/// construction). It inherits `StreamingDetokenizer`'s provenance binding
/// (only placeholders present in `mapping` are substituted, AC-013) and
/// fail-safe behavior (a mutated near-match or unknown placeholder-shaped
/// span passes through verbatim, never yielding a secret, AC-014).
pub fn detokenize(text: &str, mapping: &Mapping) -> String {
    let mut detokenizer = StreamingDetokenizer::new(mapping);
    let mut output = detokenizer.push(text);
    output.push_str(&detokenizer.finish());
    output
}

/// Length of the longest suffix of `buffer` that is also a proper prefix of
/// `PLACEHOLDER_PREFIX` — the longest trailing fragment that could still
/// grow into a full `PLACEHOLDER_PREFIX` match given more input.
fn partial_prefix_suffix_len(buffer: &str) -> usize {
    let max_check = buffer.len().min(PLACEHOLDER_PREFIX.len() - 1);
    (1..=max_check)
        .rev()
        .find(|&len| buffer.ends_with(&PLACEHOLDER_PREFIX[..len]))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
