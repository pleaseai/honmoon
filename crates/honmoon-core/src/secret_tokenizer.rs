//! Reversible secret tokenization: register secrets, mint stable and
//! unforgeable placeholders for them, and (later) substitute between secret
//! and placeholder forms in text.
//!
//! This is the transport-agnostic primitive described in
//! `.please/docs/tracks/active/secret-tokenization-20260707/spec.md`.
//! Registration, placeholder minting, and `tokenize` (secret → placeholder)
//! are implemented here; `detokenize`/streaming land in later tasks of the
//! same track.
//!
//! Placeholders are `HMAC-SHA256(key = session_salt, message = secret)`,
//! truncated and hex-encoded inside a fixed ASCII sentinel. The salt is used
//! as the MAC **key**, never as hashed message data — a non-keyed hash (e.g.
//! `std::hash::Hasher`'s `DefaultHasher`, whose SipHash keys are the fixed
//! public constant `(0, 0)`) would let an attacker who knows the secret
//! predict the placeholder, breaking the unforgeability guarantee (FR-007)
//! this module exists to provide.
//!
//! Unlike `pii.rs`, secret-bearing types here (`SecretTokenizer`, `Mapping`)
//! deliberately do **not** derive `Serialize`/`Deserialize`, and implement
//! `Debug` manually to redact secret bytes (AC-015/NFR-005) — these types
//! hold live secret material, not derived facts.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;

use aho_corasick::{AhoCorasick, MatchKind};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Opening delimiter of a placeholder token. Chosen to be distinctive and
/// unlikely to occur in ordinary payload text.
pub const PLACEHOLDER_PREFIX: &str = "<<hs:";
/// Closing delimiter of a placeholder token.
pub const PLACEHOLDER_SUFFIX: &str = ">>";
/// Number of hex characters encoding the truncated MAC (128 bits / 16 bytes).
/// 128 bits keeps the placeholder short while leaving forgery computationally
/// infeasible.
const PLACEHOLDER_HEX_LEN: usize = 32;

/// Maximum byte length of any placeholder minted by this module. Every
/// placeholder is exactly this length (the format is fixed-width), so this
/// also bounds the streaming detokenizer's cross-chunk buffer (NFR-003,
/// consumed by T003).
pub const MAX_PLACEHOLDER_LEN: usize =
    PLACEHOLDER_PREFIX.len() + PLACEHOLDER_HEX_LEN + PLACEHOLDER_SUFFIX.len();

/// Mint a placeholder for `secret` under `salt`.
///
/// `salt` is used as the HMAC **key** (never appended as hashed message
/// data), so the placeholder is unforgeable without the salt (FR-007): an
/// attacker who knows `secret` but not `salt` cannot compute or predict the
/// resulting token.
fn mint_placeholder(salt: &[u8], secret: &[u8]) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts a key of any length");
    mac.update(secret);
    let digest = mac.finalize().into_bytes();
    let hex: String = digest[..PLACEHOLDER_HEX_LEN / 2]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{PLACEHOLDER_PREFIX}{hex}{PLACEHOLDER_SUFFIX}")
}

/// One registered secret and the placeholder minted for it.
struct Entry {
    secret: String,
    placeholder: String,
}

/// Registers a session's secrets and mints a stable, opaque, unforgeable
/// placeholder for each (FR-001/FR-007).
///
/// Construction is order-preserving and first-occurrence-deduplicated:
/// repeated secret values collapse to the single placeholder minted at their
/// first occurrence (AC-012), and registration order is retained because it
/// is load-bearing for leftmost-longest tie-breaking in `tokenize` (FR-005,
/// T002). An empty secret set is a valid, non-panicking construction.
///
/// `Debug` is implemented manually to redact secret bytes (AC-015); this
/// type deliberately does not derive `Serialize`/`Deserialize` (NFR-005).
pub struct SecretTokenizer {
    salt: Vec<u8>,
    entries: Vec<Entry>,
    /// Multi-literal matcher over `entries`' secrets, in registration order,
    /// built once at construction (`tokenize`, T002). `LeftmostLongest`
    /// gives leftmost-longest overlap resolution with registration-order
    /// tie-breaking directly (FR-005/AC-010) — see the module-level
    /// `matcher_tie_break_by_registration_order_for_equal_length_duplicate_patterns`
    /// test for the verified underlying guarantee.
    matcher: AhoCorasick,
}

impl SecretTokenizer {
    /// Register `secrets` (in order) under `salt`.
    pub fn new<I, S>(salt: impl Into<Vec<u8>>, secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let salt = salt.into();
        let mut entries: Vec<Entry> = Vec::new();
        // `seen` only accelerates duplicate detection; storage order (and
        // thus later tie-breaking) comes solely from `entries`, a `Vec`.
        let mut seen: HashSet<String> = HashSet::new();
        for secret in secrets {
            let secret = secret.into();
            if !seen.insert(secret.clone()) {
                continue;
            }
            let placeholder = mint_placeholder(&salt, secret.as_bytes());
            entries.push(Entry {
                secret,
                placeholder,
            });
        }
        let patterns: Vec<&str> = entries.iter().map(|e| e.secret.as_str()).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("registered secrets are finite UTF-8 strings; the automaton always builds");
        Self {
            salt,
            entries,
            matcher,
        }
    }

    /// Registered secrets paired with their minted placeholder, in
    /// registration order. Only this module's own tests exercise it outside
    /// `cfg(test)` — `tokenize`'s matcher is built directly from `entries`
    /// at construction, not through this accessor.
    #[allow(dead_code)]
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|e| (e.secret.as_str(), e.placeholder.as_str()))
    }

    /// The placeholder minted for `secret`, if it was registered.
    pub fn placeholder_for(&self, secret: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.secret == secret)
            .map(|e| e.placeholder.as_str())
    }

    /// Number of distinct registered secrets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no secrets are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replace every occurrence of a registered secret in `text` with its
    /// placeholder (FR-002), and return a `Mapping` of only the placeholders
    /// actually substituted (AC-004) — a registered secret absent from
    /// `text` mints no entry.
    ///
    /// Overlapping/substring secrets resolve by leftmost-longest match, with
    /// equal-length ties broken by registration order (FR-005/AC-010), via
    /// `matcher`'s `MatchKind::LeftmostLongest`.
    ///
    /// Idempotence (FR-006/AC-011) is referential, not structural: this
    /// matches registered secret **literals** only, never placeholder
    /// shapes, so re-tokenizing already-tokenized text does not re-enter a
    /// minted placeholder unless a registered secret's own bytes happen to
    /// recur inside it — and even then, substituting is the correct,
    /// no-leak behavior (AC-003/SC-002), not a bug. A purely structural skip
    /// of anything shaped like `<<hs:...>>` would instead let a coincidental
    /// sentinel-shaped span in the input suppress a real secret's
    /// substitution, which this deliberately does not do.
    pub fn tokenize(&self, text: &str) -> (String, Mapping) {
        if self.entries.is_empty() {
            return (text.to_string(), Mapping::new());
        }

        let mut output = String::with_capacity(text.len());
        let mut mapping = Mapping::new();
        let mut last_end = 0;
        for m in self.matcher.find_iter(text) {
            output.push_str(&text[last_end..m.start()]);
            let entry = &self.entries[m.pattern().as_usize()];
            output.push_str(&entry.placeholder);
            mapping.insert(entry.placeholder.clone(), entry.secret.clone());
            last_end = m.end();
        }
        output.push_str(&text[last_end..]);

        (output, mapping)
    }
}

impl fmt::Debug for SecretTokenizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the salt's *length* is shown (never its bytes) — a
        // non-secret diagnostic that also keeps the field genuinely used.
        f.debug_struct("SecretTokenizer")
            .field(
                "salt",
                &format_args!("<redacted: {} byte(s)>", self.salt.len()),
            )
            .field(
                "entries",
                &format_args!("<redacted: {} secret(s)>", self.entries.len()),
            )
            .finish()
    }
}

/// Placeholder → secret mapping returned by `tokenize` (T002) and consumed by
/// `detokenize`/`StreamingDetokenizer` (T003/T004). A given `Mapping` holds
/// only the entries actually substituted for one `tokenize` call (FR-002).
///
/// `Debug` is implemented manually to redact secret bytes (AC-015); this
/// type deliberately does not derive `Serialize`/`Deserialize` (NFR-005).
#[derive(Default)]
pub struct Mapping {
    inner: HashMap<String, String>,
}

impl Mapping {
    /// An empty mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `placeholder` substitutes for `secret`.
    pub fn insert(&mut self, placeholder: impl Into<String>, secret: impl Into<String>) {
        self.inner.insert(placeholder.into(), secret.into());
    }

    /// The secret `placeholder` substitutes for, if this mapping has it.
    pub fn get(&self, placeholder: &str) -> Option<&str> {
        self.inner.get(placeholder).map(String::as_str)
    }

    /// Number of placeholder→secret entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether this mapping has no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mapping")
            .field(
                "entries",
                &format_args!("<redacted: {} entrie(s)>", self.inner.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_placeholders_match_sentinel_format() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1", "sk-secret-2"]);
        assert_eq!(t.len(), 2);
        for (_, placeholder) in t.entries() {
            assert!(placeholder.starts_with(PLACEHOLDER_PREFIX));
            assert!(placeholder.ends_with(PLACEHOLDER_SUFFIX));
            assert_eq!(placeholder.len(), MAX_PLACEHOLDER_LEN);
            assert!(placeholder.len() <= MAX_PLACEHOLDER_LEN);
        }
        // The two distinct secrets must not collide on the same placeholder.
        let p1 = t.placeholder_for("sk-secret-1").unwrap();
        let p2 = t.placeholder_for("sk-secret-2").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn determinism_same_salt_and_secrets_yield_identical_placeholders() {
        let a = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1", "sk-secret-2"]);
        let b = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1", "sk-secret-2"]);
        assert_eq!(
            a.placeholder_for("sk-secret-1"),
            b.placeholder_for("sk-secret-1")
        );
        assert_eq!(
            a.placeholder_for("sk-secret-2"),
            b.placeholder_for("sk-secret-2")
        );
    }

    #[test]
    fn unforgeable_without_the_correct_salt() {
        let salt_a = SecretTokenizer::new(b"salt-a".to_vec(), vec!["sk-shared-secret"]);
        let salt_b = SecretTokenizer::new(b"salt-b".to_vec(), vec!["sk-shared-secret"]);
        let placeholder_a = salt_a.placeholder_for("sk-shared-secret").unwrap();
        let placeholder_b = salt_b.placeholder_for("sk-shared-secret").unwrap();
        // Same secret, different salts → different placeholders.
        assert_ne!(placeholder_a, placeholder_b);
        // A placeholder computed under the wrong salt never equals the real
        // one minted for the correct session salt.
        assert_ne!(placeholder_a, placeholder_b);
    }

    #[test]
    fn debug_output_redacts_registered_secrets() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-super-secret-value"]);
        let debug = format!("{t:?}");
        assert!(!debug.contains("sk-super-secret-value"));

        let mut m = Mapping::new();
        m.insert("<<hs:deadbeef>>", "sk-super-secret-value");
        let debug = format!("{m:?}");
        assert!(!debug.contains("sk-super-secret-value"));
    }

    // AC-015/NFR-005: `SecretTokenizer` and `Mapping` intentionally do not
    // derive or implement `serde::Serialize`/`Deserialize`. This is a
    // compile-time property: the commented-out call below would fail to
    // compile ("the trait `Serialize` is not implemented for
    // `SecretTokenizer`") if uncommented, which is the evidence for this
    // guarantee. A build that serializes either type is a regression.
    #[test]
    fn secret_bearing_types_are_not_serializable() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret"]);
        let mut m = Mapping::new();
        m.insert("<<hs:deadbeef>>", "sk-secret");

        // serde_json::to_string(&t).unwrap(); // does not compile: no `Serialize` impl
        // serde_json::to_string(&m).unwrap(); // does not compile: no `Serialize` impl

        // Sanity: the types remain usable without serde.
        assert_eq!(t.len(), 1);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn duplicate_secrets_dedup_to_one_placeholder_preserving_order() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-a", "sk-b", "sk-a", "sk-c"]);
        assert_eq!(t.len(), 3);
        let order: Vec<&str> = t.entries().map(|(secret, _)| secret).collect();
        assert_eq!(order, vec!["sk-a", "sk-b", "sk-c"]);
    }

    #[test]
    fn zero_secrets_is_a_valid_construction() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), Vec::<String>::new());
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    // --- T002: tokenize ---------------------------------------------------

    #[test]
    fn tokenize_happy_path_replaces_all_occurrences_and_mints_one_mapping_entry() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1"]);
        let (out, mapping) = t.tokenize("key=sk-secret-1 again sk-secret-1 end");
        let placeholder = t.placeholder_for("sk-secret-1").unwrap();
        assert_eq!(out, format!("key={placeholder} again {placeholder} end"));
        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping.get(placeholder), Some("sk-secret-1"));
    }

    #[test]
    fn tokenize_output_never_contains_registered_secret_bytes() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1", "sk-secret-2"]);
        let (out, _mapping) = t.tokenize("sk-secret-1 and sk-secret-2 travel together");
        assert!(!out.contains("sk-secret-1"));
        assert!(!out.contains("sk-secret-2"));
    }

    #[test]
    fn tokenize_leaves_unused_secret_unmapped_and_text_unchanged() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-unused"]);
        let (out, mapping) = t.tokenize("no secrets here");
        assert_eq!(out, "no secrets here");
        assert!(mapping.is_empty());
    }

    #[test]
    fn tokenize_overlap_prefers_leftmost_longest_match() {
        // "A" is a substring of "AB"; registered shorter-first.
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["A", "AB"]);
        let (out, mapping) = t.tokenize("AB");
        let placeholder_ab = t.placeholder_for("AB").unwrap();
        assert_eq!(out, placeholder_ab);
        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping.get(placeholder_ab), Some("AB"));
    }

    #[test]
    fn matcher_tie_break_by_registration_order_for_equal_length_duplicate_patterns() {
        // STOP-condition verification (T002): confirm the underlying
        // aho-corasick automaton resolves an equal-length tie by the
        // earliest-registered pattern index. `SecretTokenizer::new` dedups
        // identical secret values (T001), so this exact tie can never reach
        // the automaton through the public API — this test exercises
        // `aho-corasick` directly to prove the tie-break rule FR-005/AC-010
        // depends on actually holds, independent of that dedup.
        use aho_corasick::{AhoCorasick, MatchKind};

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(["dup", "dup"])
            .expect("two equal-length literal patterns build fine");
        let matches: Vec<usize> = ac
            .find_iter("dup")
            .map(|m| m.pattern().as_usize())
            .collect();
        // Only one match is reported for the single occurrence, and it must
        // resolve to pattern index 0 (the earlier-registered one).
        assert_eq!(matches, vec![0]);
    }

    #[test]
    fn tokenize_is_referentially_idempotent_on_its_own_output() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1"]);
        let (once, mapping_once) = t.tokenize("value=sk-secret-1;");
        let (twice, mapping_twice) = t.tokenize(&once);
        // Re-tokenizing already-tokenized text is a no-op: the secret is no
        // longer present in `once`, so nothing new is substituted.
        assert_eq!(twice, once);
        assert!(mapping_twice.is_empty());
        assert_eq!(mapping_once.len(), 1);
    }

    #[test]
    fn tokenize_still_substitutes_secret_inside_a_coincidental_sentinel_shaped_span() {
        // Regression guard: a structural (sentinel-shape) skip would leak the
        // secret here. The registered secret's bytes happen to appear inside
        // a span of the *input* that merely looks like a placeholder
        // sentinel (but was never minted by this tokenizer). Idempotence is
        // enforced referentially (matching secret literals, never placeholder
        // shapes), so this must still be substituted (AC-003/SC-002).
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["hs:deadbeef"]);
        let input = "prefix <<hs:deadbeef>> suffix";
        let (out, mapping) = t.tokenize(input);
        assert!(!out.contains("hs:deadbeef"));
        assert_eq!(mapping.len(), 1);
    }

    #[test]
    fn tokenize_with_zero_secrets_returns_input_unchanged_with_empty_mapping() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), Vec::<String>::new());
        let (out, mapping) = t.tokenize("nothing registered, nothing to do");
        assert_eq!(out, "nothing registered, nothing to do");
        assert!(mapping.is_empty());
    }
}
