//! Cross-cutting sweep over `secret_tokenizer`'s PUBLIC re-exported surface
//! (T005): proves the crate-root exports (`honmoon_core::{SecretTokenizer,
//! Mapping, StreamingDetokenizer, detokenize, MAX_PLACEHOLDER_LEN,
//! PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX}`) are reachable and complete, by
//! exercising determinism (AC-009), streaming == whole-text equivalence
//! (SC-003), and the overlap/idempotence properties (SC-005) entirely
//! through `use honmoon_core::...` — never the internal module path. This
//! is a separate integration test (its own compilation unit) specifically
//! so it can only see `pub` items, unlike the crate's own inline
//! `#[cfg(test)]` modules which can also see private/internal paths.

use honmoon_core::{
    MAX_PLACEHOLDER_LEN, Mapping, PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX, SecretTokenizer,
    StreamingDetokenizer, detokenize,
};

/// An adversarial corpus exercised entirely through the public path, mirroring
/// the internal T004 sweep but proving the *exported* names are the complete
/// public surface needed to reproduce it outside the crate.
fn corpus() -> Vec<(&'static str, SecretTokenizer, String)> {
    vec![
        (
            "secret_at_start",
            SecretTokenizer::new(b"pub-salt-start".to_vec(), vec!["sk-pub-start"]),
            "sk-pub-start and then the rest of the text".to_string(),
        ),
        (
            "repeated_secret",
            SecretTokenizer::new(b"pub-salt-repeat".to_vec(), vec!["sk-pub-repeat"]),
            "sk-pub-repeat and sk-pub-repeat and sk-pub-repeat".to_string(),
        ),
        (
            "overlapping_secrets_leftmost_longest",
            SecretTokenizer::new(b"pub-salt-overlap".to_vec(), vec!["A", "AB"]),
            "AB A AB BA A".to_string(),
        ),
        (
            "multibyte_utf8_around_secret",
            SecretTokenizer::new(b"pub-salt-utf8".to_vec(), vec!["sk-pub-multibyte"]),
            "префикс sk-pub-multibyte 한글단어 emoji😀 sk-pub-multibyte 结尾".to_string(),
        ),
        (
            "no_secrets_present",
            SecretTokenizer::new(b"pub-salt-absent".to_vec(), vec!["sk-pub-not-here"]),
            "just plain text, nothing to redact".to_string(),
        ),
    ]
}

/// Every char-boundary single-split point of `text`, as `(prefix, suffix)`.
fn all_single_splits(text: &str) -> Vec<(&str, &str)> {
    (0..=text.len())
        .filter(|&i| text.is_char_boundary(i))
        .map(|split| (&text[..split], &text[split..]))
        .collect()
}

#[test]
fn public_path_determinism_same_salt_and_secrets_yield_identical_placeholders() {
    // AC-009: identical inputs (salt + secrets) yield identical placeholders
    // and identical output on every run, reachable only via `honmoon_core::`.
    let a = SecretTokenizer::new(b"pub-determinism-salt".to_vec(), vec!["sk-a", "sk-b"]);
    let b = SecretTokenizer::new(b"pub-determinism-salt".to_vec(), vec!["sk-a", "sk-b"]);
    assert_eq!(a.placeholder_for("sk-a"), b.placeholder_for("sk-a"));
    assert_eq!(a.placeholder_for("sk-b"), b.placeholder_for("sk-b"));

    let (out_a, _) = a.tokenize("sk-a then sk-b");
    let (out_b, _) = b.tokenize("sk-a then sk-b");
    assert_eq!(out_a, out_b);
}

#[test]
fn public_path_placeholder_shape_matches_documented_sentinel_constants() {
    let t = SecretTokenizer::new(b"pub-shape-salt".to_vec(), vec!["sk-pub-shape"]);
    let placeholder = t.placeholder_for("sk-pub-shape").unwrap();
    assert!(placeholder.starts_with(PLACEHOLDER_PREFIX));
    assert!(placeholder.ends_with(PLACEHOLDER_SUFFIX));
    assert_eq!(placeholder.len(), MAX_PLACEHOLDER_LEN);
}

#[test]
fn public_path_round_trip_and_streaming_equivalence_across_corpus() {
    // SC-003/SC-005 exercised end-to-end through the public re-exports only.
    let mut total_splits = 0usize;
    for (name, tokenizer, text) in corpus() {
        let (tokenized, mapping) = tokenizer.tokenize(&text);

        // Whole-text detokenize round-trips (SC-001/AC-002).
        let whole = detokenize(&tokenized, &mapping);
        assert_eq!(whole, text, "case {name}: round-trip failed");

        // Streaming, fed through every single-split boundary, must match the
        // whole-text detokenize output byte-for-byte (SC-003).
        for (prefix, suffix) in all_single_splits(&tokenized) {
            total_splits += 1;
            let mut d = StreamingDetokenizer::new(&mapping);
            let mut streamed = d.push(prefix);
            streamed.push_str(&d.push(suffix));
            streamed.push_str(&d.finish());
            assert_eq!(
                streamed,
                whole,
                "case {name}: streaming split at {} diverged from whole-text detokenize",
                prefix.len()
            );
        }

        // Re-tokenizing the tokenized output is a no-op (SC-005 idempotence).
        let (retokenized, remapping) = tokenizer.tokenize(&tokenized);
        assert_eq!(
            retokenized, tokenized,
            "case {name}: re-tokenize was not a no-op"
        );
        assert!(
            remapping.is_empty(),
            "case {name}: re-tokenize minted new entries"
        );
    }
    assert!(
        total_splits >= 20,
        "expected a meaningful public-path boundary sweep, only exercised {total_splits} splits"
    );
}

/// A Claude-Code-shaped multi-turn request body: the same secrets recur
/// across turns because agent clients resend the full history every request.
fn multi_turn_body() -> String {
    r#"{"model":"claude-fable-5","messages":[
{"role":"user","content":"deploy with key sk-ant-api03-cache-stable and db pass hunter2-prod"},
{"role":"assistant","content":"Using sk-ant-api03-cache-stable for the deploy."},
{"role":"user","content":"rotate hunter2-prod afterwards, keep sk-ant-api03-cache-stable"}
]}"#
    .to_string()
}

#[test]
fn public_path_same_multi_turn_body_redacted_twice_is_byte_identical() {
    // Issue #20: the proxy re-redacts the resent conversation history on
    // every request, and provider prompt caching is longest-common-prefix
    // based. If two passes over the same bytes could ever differ, the cache
    // prefix would silently be invalidated each turn — so double-pass
    // byte-identity is the contract, not an implementation detail.
    let secrets = vec!["sk-ant-api03-cache-stable", "hunter2-prod"];
    let body = multi_turn_body();

    let t = SecretTokenizer::new(b"session-salt".to_vec(), secrets.clone());
    let (first, _) = t.tokenize(&body);
    let (second, _) = t.tokenize(&body);
    // Same instance, same bytes in → same bytes out (no per-call state).
    assert_eq!(first, second);

    // A tokenizer rebuilt from the same session state (next request, fresh
    // per-request construction — or a fresh process, as the CLI hook
    // transport spawns per call) must reproduce the exact bytes too.
    let rebuilt = SecretTokenizer::new(b"session-salt".to_vec(), secrets);
    let (third, _) = rebuilt.tokenize(&body);
    assert_eq!(first, third);

    // And the redaction actually happened — determinism of a no-op would
    // prove nothing.
    assert!(!first.contains("sk-ant-api03-cache-stable"));
    assert!(!first.contains("hunter2-prod"));
}

#[test]
fn public_path_redacted_bytes_are_independent_of_registration_order() {
    // Issue #20 detection stability: replacement offsets must not shift
    // between passes over the same bytes. Leftmost-longest overlap
    // resolution is a property of the *text* (longest registered secret at
    // each position wins), so permuting registration order — including a
    // secret that is a strict prefix of another — must yield byte-identical
    // output.
    let body = "a=sk-prod-key-extended; b=sk-prod-key; c=hunter2 d=sk-prod-key-extended";
    let forward = SecretTokenizer::new(
        b"order-salt".to_vec(),
        vec!["sk-prod-key", "sk-prod-key-extended", "hunter2"],
    );
    let reversed = SecretTokenizer::new(
        b"order-salt".to_vec(),
        vec!["hunter2", "sk-prod-key-extended", "sk-prod-key"],
    );
    let forward_out = forward.tokenize(body).0;
    let reversed_out = reversed.tokenize(body).0;
    assert_eq!(forward_out, reversed_out);
    // Negative control: order-independence of a no-op tokenize would prove
    // nothing, so confirm a substitution actually happened — every
    // `sk-prod-key*` occurrence is consumed by a placeholder (whose hex body
    // cannot contain the literal secret bytes).
    assert!(!forward_out.contains("sk-prod-key"));
}

#[test]
fn public_path_extending_the_history_preserves_the_redacted_prefix() {
    // The property prompt caching actually needs: the redaction of turn N's
    // messages must reappear byte-for-byte inside turn N+1's request. A real
    // next turn inserts the new message *inside* the `messages` array (before
    // the closing `]}`), not appended after it — so turn N's bytes remain a
    // prefix only up to that moved `]}`. The shared region must redact
    // identically, and it does: the insertion point sits after JSON
    // structural bytes (`"`, `}`) that no registered secret contains, so no
    // leftmost-longest match straddles it. This test exercises that ordinary
    // case; it does not construct a secret split across the insertion point.
    let t = SecretTokenizer::new(
        b"session-salt".to_vec(),
        vec!["sk-ant-api03-cache-stable", "hunter2-prod"],
    );
    let history = multi_turn_body();
    // Grow the conversation the way an agent client does: splice the next
    // turn into the array, keeping the body valid JSON. `]}` occurs exactly
    // once (the array/object close at the very end), so this replaces only
    // the closing delimiter.
    let extended = history.replace(
        "]}",
        ",\n{\"role\":\"assistant\",\"content\":\"rotated hunter2-prod as asked\"}\n]}",
    );

    let (redacted_history, _) = t.tokenize(&history);
    let (redacted_extended, _) = t.tokenize(&extended);
    // Everything up to (not including) the moved `]}` must redact identically.
    let prefix_len = redacted_history.len() - "]}".len();
    assert_eq!(
        &redacted_extended[..prefix_len],
        &redacted_history[..prefix_len],
        "growing the history must preserve the redacted prefix of prior messages"
    );
    // Negative control: the assertion above holds trivially under a no-op
    // tokenize, so confirm redaction actually happened in the shared prefix.
    assert!(!redacted_history.contains("sk-ant-api03-cache-stable"));
    assert!(!redacted_history.contains("hunter2-prod"));
}

#[test]
fn public_path_overlap_leftmost_longest_and_provenance_binding() {
    // SC-005 overlap resolution, reachable only via `honmoon_core::`.
    let t = SecretTokenizer::new(b"pub-overlap-salt".to_vec(), vec!["A", "AB"]);
    let (out, mapping) = t.tokenize("AB");
    let placeholder_ab = t.placeholder_for("AB").unwrap();
    assert_eq!(out, placeholder_ab);
    assert_eq!(mapping.len(), 1);

    // Provenance binding (AC-013): an empty mapping never substitutes an
    // unrelated placeholder-shaped token, even via the public path.
    let unrelated_mapping = Mapping::new();
    let untouched = detokenize(placeholder_ab, &unrelated_mapping);
    assert_eq!(untouched, placeholder_ab);
}
