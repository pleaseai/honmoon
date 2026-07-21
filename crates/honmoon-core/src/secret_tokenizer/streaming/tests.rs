use super::super::{PLACEHOLDER_SUFFIX, SecretTokenizer};
use super::*;

/// Build a one-entry `Mapping` plus the real placeholder/secret pair, so
/// tests can assemble adversarial byte sequences around a genuine entry.
fn one_entry_mapping() -> (Mapping, String, &'static str) {
    let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-stream-secret"]);
    let placeholder = t.placeholder_for("sk-stream-secret").unwrap().to_string();
    let mut mapping = Mapping::new();
    mapping.insert(placeholder.clone(), "sk-stream-secret");
    (mapping, placeholder, "sk-stream-secret")
}

#[test]
fn owned_constructor_detokenizes_identically_to_borrowed() {
    let (mapping, placeholder, secret) = one_entry_mapping();
    let text = format!("before {placeholder} after");

    let mut borrowed = StreamingDetokenizer::new(&mapping);
    let mut borrowed_output = borrowed.push(&text);
    borrowed_output.push_str(&borrowed.finish());

    let mut owned = StreamingDetokenizer::owned(mapping);
    let mut owned_output = owned.push(&text);
    owned_output.push_str(&owned.finish());

    assert_eq!(owned_output, borrowed_output);
    assert_eq!(owned_output, format!("before {secret} after"));
}

#[test]
fn streaming_happy_path_recognizes_placeholder_split_across_every_boundary() {
    let (mapping, placeholder, secret) = one_entry_mapping();
    let text = format!("before {placeholder} after");
    let expected = format!("before {secret} after");

    for split in 0..=text.len() {
        if !text.is_char_boundary(split) {
            continue;
        }
        let mut d = StreamingDetokenizer::new(&mapping);
        let mut out = d.push(&text[..split]);
        out.push_str(&d.push(&text[split..]));
        out.push_str(&d.finish());
        assert_eq!(out, expected, "split at byte {split} failed");
    }
}

#[test]
fn streaming_no_partial_prefix_emitted_while_chunks_arrive() {
    let (mapping, placeholder, _secret) = one_entry_mapping();
    let mut d = StreamingDetokenizer::new(&mapping);
    // Feed everything except the last byte of the placeholder: nothing
    // about an as-yet-incomplete placeholder may be emitted (AC-006).
    let out = d.push(&placeholder[..placeholder.len() - 1]);
    assert_eq!(out, "");
}

#[test]
fn streaming_finish_flushes_incomplete_placeholder_verbatim_no_secret() {
    let (mapping, placeholder, secret) = one_entry_mapping();
    let mut d = StreamingDetokenizer::new(&mapping);
    let partial = &placeholder[..placeholder.len() - 1];
    let mut out = d.push(partial);
    assert_eq!(out, "");
    out.push_str(&d.finish());
    // The buffered prefix is emitted verbatim; no secret ever appears.
    assert_eq!(out, partial);
    assert!(!out.contains(secret));
}

#[test]
fn streaming_false_start_still_recognizes_genuine_placeholder_after_rescan() {
    let (mapping, placeholder, secret) = one_entry_mapping();
    // A false start (`PLACEHOLDER_PREFIX`) immediately followed by a
    // genuine placeholder in the same buffered window.
    let text = format!("{PLACEHOLDER_PREFIX}{placeholder}");
    let mut d = StreamingDetokenizer::new(&mapping);
    let mut out = d.push(&text);
    out.push_str(&d.finish());
    // The invalidated false start is literal text; the real placeholder
    // is still matched and substituted.
    assert_eq!(out, format!("{PLACEHOLDER_PREFIX}{secret}"));
    assert!(!out.contains(&placeholder));
}

#[test]
fn streaming_non_ascii_in_prefix_window_does_not_drop_a_following_placeholder() {
    // Regression (gemini-code-assist review of PR #15): a `<<hs:` false
    // start whose MAX_PLACEHOLDER_LEN window straddles a multi-byte UTF-8
    // char must NOT flush-and-clear the whole buffer — a genuine
    // placeholder later in the buffer would be lost, breaking AC-005.
    let (mapping, placeholder, secret) = one_entry_mapping();
    // `<<hs:` (5 ASCII bytes) + 20×"가" (3 bytes each) → byte 39 lands
    // mid-character, so `is_char_boundary(MAX_PLACEHOLDER_LEN)` is false
    // while the buffer already holds ≥ MAX_PLACEHOLDER_LEN bytes.
    let filler = "가".repeat(20);
    let text = format!("{PLACEHOLDER_PREFIX}{filler}{placeholder}");
    let expected = format!("{PLACEHOLDER_PREFIX}{filler}{secret}");

    // Whole push, and every char-boundary split, must all round-trip.
    let mut d = StreamingDetokenizer::new(&mapping);
    let mut out = d.push(&text);
    out.push_str(&d.finish());
    assert_eq!(out, expected);
    assert!(out.contains(secret));
    assert!(!out.contains(&placeholder));

    for split in 0..=text.len() {
        if !text.is_char_boundary(split) {
            continue;
        }
        let mut d = StreamingDetokenizer::new(&mapping);
        let mut o = d.push(&text[..split]);
        o.push_str(&d.push(&text[split..]));
        o.push_str(&d.finish());
        assert_eq!(o, expected, "split at byte {split} dropped the placeholder");
    }
}

#[test]
fn streaming_large_false_start_heavy_input_stays_correct_and_linear() {
    // A big chunk densely packed with `<<hs:` false starts around a single
    // genuine placeholder. This is the adversarial shape that made the old
    // front-`drain(..1)` rescan O(N^2); the index-scan rewrite must both
    // stay fast and detokenize correctly. We assert correctness (matching
    // whole-text `detokenize`) — the linearity is what keeps it from
    // timing out on this ~50 KB input.
    let (mapping, placeholder, secret) = one_entry_mapping();
    let noise = PLACEHOLDER_PREFIX.repeat(10_000); // 50 KB of false starts
    let text = format!("{noise}{placeholder}{noise}");
    let expected = format!("{noise}{secret}{noise}");

    // Whole-text path.
    assert_eq!(detokenize(&text, &mapping), expected);

    // Streamed in fixed-size chunks (crosses many false-start boundaries).
    let bytes = text.as_bytes();
    let mut d = StreamingDetokenizer::new(&mapping);
    let mut out = String::new();
    for chunk in bytes.chunks(7) {
        out.push_str(&d.push(std::str::from_utf8(chunk).unwrap()));
    }
    out.push_str(&d.finish());
    assert_eq!(out, expected);
    assert!(!out.contains(&placeholder));
}

#[test]
fn streaming_unknown_placeholder_shaped_token_passes_through_verbatim() {
    // Placeholder-shaped (right prefix/length/suffix) but never minted
    // into any mapping — provenance binding must leave it untouched
    // (AC-013/FR-008).
    let unknown = format!("{PLACEHOLDER_PREFIX}{}{PLACEHOLDER_SUFFIX}", "0".repeat(32));
    assert_eq!(unknown.len(), MAX_PLACEHOLDER_LEN);
    let mapping = Mapping::new();
    let mut d = StreamingDetokenizer::new(&mapping);
    let mut out = d.push(&format!("prefix {unknown} suffix"));
    out.push_str(&d.finish());
    assert_eq!(out, format!("prefix {unknown} suffix"));
}

#[test]
fn streaming_forged_placeholder_mid_stream_never_leaks_secret() {
    let (mapping, placeholder, secret) = one_entry_mapping();
    // Mutate one hex character of the real placeholder: a near-match
    // that must not resolve to the real secret (AC-014/SC-004).
    let mut forged = placeholder.clone();
    let mutate_at = PLACEHOLDER_PREFIX.len();
    let mutated_char = if forged.as_bytes()[mutate_at] == b'0' {
        b'1'
    } else {
        b'0'
    };
    // Replace one ASCII hex byte in-place (safe: single-byte ASCII).
    unsafe {
        forged.as_bytes_mut()[mutate_at] = mutated_char;
    }
    assert_ne!(forged, placeholder);

    let mut d = StreamingDetokenizer::new(&mapping);
    let mut out = d.push(&format!("start {forged} end"));
    out.push_str(&d.finish());
    assert_eq!(out, format!("start {forged} end"));
    assert!(!out.contains(secret));
}

#[test]
fn streaming_buffer_never_exceeds_max_placeholder_len_bound() {
    let (mapping, _placeholder, _secret) = one_entry_mapping();
    let mut d = StreamingDetokenizer::new(&mapping);
    // A long run of never-completing partial-placeholder-like prefixes:
    // each push adds another `PLACEHOLDER_PREFIX` with no valid hex/
    // suffix ever following, so nothing ever resolves into a match.
    for _ in 0..200 {
        let _ = d.push(PLACEHOLDER_PREFIX);
        assert!(
            d.buffered_len() <= MAX_PLACEHOLDER_LEN,
            "buffer grew past the bound: {} bytes",
            d.buffered_len()
        );
    }
}

#[test]
fn streaming_empty_chunk_push_is_a_no_op() {
    let (mapping, _placeholder, _secret) = one_entry_mapping();
    let mut d = StreamingDetokenizer::new(&mapping);
    assert_eq!(d.push(""), "");
    assert_eq!(d.buffered_len(), 0);

    // Also a no-op mid-stream, without disturbing buffered state.
    let _ = d.push("<<hs:");
    assert_eq!(d.buffered_len(), PLACEHOLDER_PREFIX.len());
    assert_eq!(d.push(""), "");
    assert_eq!(d.buffered_len(), PLACEHOLDER_PREFIX.len());
}

// --- T004: whole-text `detokenize` + round-trip/equivalence corpus -----

/// An adversarial corpus of (name, tokenizer, original text) triples,
/// covering secrets at the start/middle/end/adjacent, repeated and
/// overlapping secrets, secrets containing regex/sentinel-ish
/// characters, multi-byte UTF-8 around secrets, empty text, and text
/// with no secrets present. Fixed salts and secrets only — no
/// randomness, so the sweep is fully deterministic.
fn corpus() -> Vec<(&'static str, SecretTokenizer, String)> {
    vec![
        (
            "secret_at_start",
            SecretTokenizer::new(b"salt-start".to_vec(), vec!["sk-start-secret"]),
            "sk-start-secret and then the rest of the text".to_string(),
        ),
        (
            "secret_at_end",
            SecretTokenizer::new(b"salt-end".to_vec(), vec!["sk-end-secret"]),
            "the text leads up to sk-end-secret".to_string(),
        ),
        (
            "secret_in_middle",
            SecretTokenizer::new(b"salt-middle".to_vec(), vec!["sk-middle-secret"]),
            "before sk-middle-secret after".to_string(),
        ),
        (
            "adjacent_secrets_no_separator",
            SecretTokenizer::new(b"salt-adjacent".to_vec(), vec!["sk-a", "sk-b"]),
            "sk-ask-b".to_string(),
        ),
        (
            "repeated_secret",
            SecretTokenizer::new(b"salt-repeat".to_vec(), vec!["sk-repeat-me"]),
            "sk-repeat-me and sk-repeat-me and sk-repeat-me".to_string(),
        ),
        (
            "overlapping_secrets_leftmost_longest",
            SecretTokenizer::new(b"salt-overlap".to_vec(), vec!["A", "AB"]),
            "AB A AB BA A".to_string(),
        ),
        (
            "secret_with_regex_special_chars",
            SecretTokenizer::new(b"salt-regex".to_vec(), vec!["sk-.*+?()[]{}"]),
            "value=sk-.*+?()[]{} end".to_string(),
        ),
        (
            "secret_containing_sentinel_ish_chars",
            SecretTokenizer::new(b"salt-sentinel".to_vec(), vec!["<<hs:notreal>>"]),
            "text <<hs:notreal>> more".to_string(),
        ),
        (
            "multibyte_utf8_around_secret",
            SecretTokenizer::new(b"salt-utf8".to_vec(), vec!["sk-multibyte"]),
            "префикс sk-multibyte 한글단어 emoji😀 sk-multibyte 结尾".to_string(),
        ),
        (
            "empty_text",
            SecretTokenizer::new(b"salt-empty".to_vec(), vec!["sk-unused"]),
            String::new(),
        ),
        (
            "no_secrets_present",
            SecretTokenizer::new(b"salt-absent".to_vec(), vec!["sk-not-here"]),
            "just plain text, nothing to redact".to_string(),
        ),
    ]
}

/// Every way to split `text` into two pieces at a char boundary
/// (including the empty-first/empty-last splits), plus a handful of
/// 3-/4-way splits at evenly spaced char boundaries — an exhaustive
/// sweep over single-split boundaries, with a few multi-split
/// partitions layered on top.
fn all_partitions(text: &str) -> Vec<Vec<&str>> {
    let boundaries: Vec<usize> = (0..=text.len())
        .filter(|&i| text.is_char_boundary(i))
        .collect();

    let mut partitions: Vec<Vec<&str>> = boundaries
        .iter()
        .map(|&split| vec![&text[..split], &text[split..]])
        .collect();

    if boundaries.len() >= 4 {
        let n = boundaries.len();
        let mut points = vec![boundaries[n / 4], boundaries[n / 2], boundaries[3 * n / 4]];
        points.sort_unstable();
        points.dedup();
        let mut pieces = Vec::with_capacity(points.len() + 1);
        let mut prev = 0;
        for &p in &points {
            pieces.push(&text[prev..p]);
            prev = p;
        }
        pieces.push(&text[prev..]);
        partitions.push(pieces);
    }

    partitions
}

/// Feed `partition`'s pieces through a fresh `StreamingDetokenizer` in
/// order and return the concatenated output.
fn feed_partition(partition: &[&str], mapping: &Mapping) -> String {
    let mut d = StreamingDetokenizer::new(mapping);
    let mut out = String::new();
    for chunk in partition {
        out.push_str(&d.push(chunk));
    }
    out.push_str(&d.finish());
    out
}

#[test]
fn detokenize_round_trips_tokenize_output_across_corpus() {
    for (name, tokenizer, text) in corpus() {
        let (tokenized, mapping) = tokenizer.tokenize(&text);
        let restored = detokenize(&tokenized, &mapping);
        assert_eq!(restored, text, "round-trip failed for case: {name}");
    }
}

#[test]
fn streaming_output_matches_whole_text_detokenize_for_every_partition() {
    let mut total_partitions = 0usize;
    for (name, tokenizer, text) in corpus() {
        let (tokenized, mapping) = tokenizer.tokenize(&text);
        let expected = detokenize(&tokenized, &mapping);
        for partition in all_partitions(&tokenized) {
            total_partitions += 1;
            let actual = feed_partition(&partition, &mapping);
            assert_eq!(
                actual, expected,
                "case {name} partition {partition:?} diverged from whole-text detokenize"
            );
        }
    }
    // Sanity: the sweep actually exercised a meaningful number of
    // boundary partitions, not just a handful of trivial cases.
    assert!(
        total_partitions >= 50,
        "expected a broad boundary sweep, only exercised {total_partitions} partitions"
    );
}

#[test]
fn detokenize_leaves_mutated_placeholder_near_match_unchanged() {
    // AC-014: a mutated near-match of a real placeholder must be left
    // unchanged in whole-text `detokenize`, and never yield the secret.
    let tokenizer = SecretTokenizer::new(b"salt-mutation".to_vec(), vec!["sk-mutation-secret"]);
    let placeholder = tokenizer
        .placeholder_for("sk-mutation-secret")
        .unwrap()
        .to_string();
    let mut mapping = Mapping::new();
    mapping.insert(placeholder.clone(), "sk-mutation-secret");

    let mut forged = placeholder.clone();
    let mutate_at = PLACEHOLDER_PREFIX.len();
    let mutated_byte = if forged.as_bytes()[mutate_at] == b'0' {
        b'1'
    } else {
        b'0'
    };
    // Replace one ASCII hex byte in-place (safe: single-byte ASCII).
    unsafe {
        forged.as_bytes_mut()[mutate_at] = mutated_byte;
    }
    assert_ne!(forged, placeholder);

    let text = format!("start {forged} end");
    let out = detokenize(&text, &mapping);
    assert_eq!(out, text);
    assert!(!out.contains("sk-mutation-secret"));
}
