//! Reversible secret tokenization: register secrets, mint stable and
//! unforgeable placeholders for them, and substitute between secret and
//! placeholder forms in text.
//!
//! This is the transport-agnostic primitive described in the
//! `secret-tokenization-20260707` track spec. Registration, placeholder
//! minting, `tokenize` (secret → placeholder), whole-text `detokenize`, and a
//! boundary-safe [`StreamingDetokenizer`] are all implemented here. The proxy
//! wire path and management hook transport share these primitives and one live
//! mapping store.
//!
//! Placeholders are `HMAC-SHA256(key = session_salt, message = secret)`,
//! truncated and hex-encoded inside a fixed ASCII sentinel. The salt is used
//! as the MAC **key**, never as hashed message data — a non-keyed hash (e.g.
//! `std::hash::Hasher`'s `DefaultHasher`, whose SipHash keys are the fixed
//! public constant `(0, 0)`) would let an attacker who knows the secret
//! predict the placeholder, breaking the unforgeability guarantee (FR-007)
//! this module exists to provide.
//!
//! # Determinism — prompt-cache prefix stability (issue #20)
//!
//! Redaction is deterministic, byte for byte. Two properties combine to
//! guarantee it:
//!
//! - **Minting is a pure function of `(salt, secret)`.** No counters, no
//!   RNG, no per-call or per-instance state: the same secret under the same
//!   session salt always mints the identical placeholder — across calls,
//!   across independently constructed tokenizers, and across process
//!   restarts.
//! - **Match boundaries depend only on the input text.** Substitution runs a
//!   leftmost-longest multi-literal automaton ([`AhoCorasick`] with
//!   [`MatchKind::LeftmostLongest`]): at each position the longest registered
//!   secret wins, so overlap resolution — and therefore every replacement
//!   offset — is a property of the text, not of registration order,
//!   alternation order, or any prior `tokenize` call.
//!
//! Consequently, running the same bytes through `tokenize` any number of
//! times yields the same bytes. This is load-bearing for cost: agent clients
//! (e.g. Claude Code) resend the full conversation history on every request,
//! and provider prompt caching works on a longest-common-prefix basis — if
//! re-redacting that history could ever produce different bytes for the same
//! secret occurrence, the request prefix would diverge at the first
//! occurrence and silently invalidate the entire prompt-cache prefix every
//! turn. The guarantee covers redaction (`tokenize`) only; detokenization
//! and `Mapping` disclosure semantics are a separate discussion (issue #16).
//!
//! Unlike `pii.rs`, secret-bearing types here (`SecretTokenizer`, `Mapping`)
//! deliberately do **not** derive `Serialize`/`Deserialize`, and implement
//! `Debug` manually to redact secret bytes (AC-015/NFR-005) — these types
//! hold live secret material, not derived facts.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Mutex;

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
    // Build the whole placeholder in a single allocation: prefix, the
    // hex-encoded truncated digest written byte-by-byte (no per-byte
    // `String`), then suffix. Writing into a `String` is infallible.
    let mut placeholder = String::with_capacity(MAX_PLACEHOLDER_LEN);
    placeholder.push_str(PLACEHOLDER_PREFIX);
    for byte in &digest[..PLACEHOLDER_HEX_LEN / 2] {
        let _ = write!(placeholder, "{byte:02x}");
    }
    placeholder.push_str(PLACEHOLDER_SUFFIX);
    placeholder
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

/// Error constructing a [`SecretTokenizer`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretTokenizerError {
    /// The session salt was empty. The salt is the HMAC **key** that makes
    /// placeholders unforgeable (FR-007); an empty key makes every placeholder
    /// publicly reproducible for a known secret, so construction fails closed
    /// rather than mint forgeable tokens.
    #[error("session salt must not be empty")]
    EmptySalt,
}

impl SecretTokenizer {
    /// Register `secrets` (in order) under `salt`, failing closed when `salt`
    /// is empty.
    ///
    /// The salt is the HMAC key behind placeholder unforgeability (FR-007), so
    /// an empty salt is rejected with [`SecretTokenizerError::EmptySalt`]
    /// instead of silently minting publicly-reproducible placeholders. (Salt
    /// *entropy* is the caller's responsibility, NFR-002; this only rejects
    /// the degenerate empty case the type system can catch.)
    pub fn try_new<I, S>(salt: impl Into<Vec<u8>>, secrets: I) -> Result<Self, SecretTokenizerError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let salt = salt.into();
        if salt.is_empty() {
            return Err(SecretTokenizerError::EmptySalt);
        }
        let mut entries: Vec<Entry> = Vec::new();
        // `seen` only accelerates duplicate detection; storage order (and
        // thus later tie-breaking) comes solely from `entries`, a `Vec`.
        let mut seen: HashSet<String> = HashSet::new();
        for secret in secrets {
            let secret = secret.into();
            // An empty secret is meaningless and dangerous: an empty
            // aho-corasick pattern matches at every position, which would
            // splice a placeholder between every byte (or wedge the match
            // loop). Skip it defensively rather than trusting the caller.
            if secret.is_empty() {
                continue;
            }
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
        Ok(Self {
            salt,
            entries,
            matcher,
        })
    }

    /// Register `secrets` (in order) under `salt`.
    ///
    /// Convenience wrapper over [`try_new`](Self::try_new) for callers with a
    /// known-valid (non-empty) salt. **Panics** if `salt` is empty; use
    /// `try_new` to handle that as a recoverable error (e.g. a config fault in
    /// the data plane).
    pub fn new<I, S>(salt: impl Into<Vec<u8>>, secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::try_new(salt, secrets).expect("session salt must not be empty")
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
#[derive(Clone, Default)]
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

    /// Merge all entries from `other` into this mapping.
    ///
    /// Used by transport adapters that redact multiple JSON string leaves and
    /// keep one live reverse mapping for the resulting verdict.
    pub fn extend(&mut self, other: Mapping) {
        self.inner.extend(other.inner);
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

/// One retained placeholder→secret entry plus the recency sequence number it
/// was last recorded under.
struct StoreEntry {
    secret: String,
    seq: u64,
}

/// Interior state of [`MappingStore`]: the placeholder→secret map plus a
/// recency index (`seq → placeholder`) whose first key is always the
/// least-recently-recorded entry, making eviction `O(log n)`.
#[derive(Default)]
struct BoundedMapping {
    entries: HashMap<String, StoreEntry>,
    by_recency: BTreeMap<u64, String>,
    next_seq: u64,
    evicted: u64,
}

impl BoundedMapping {
    /// Insert or refresh one entry, bumping its recency either way.
    fn insert(&mut self, placeholder: String, secret: String) {
        let seq = self.next_seq;
        self.next_seq += 1;
        if let Some(previous) = self
            .entries
            .insert(placeholder.clone(), StoreEntry { secret, seq })
        {
            self.by_recency.remove(&previous.seq);
        }
        self.by_recency.insert(seq, placeholder);
    }

    /// Drop least-recently-recorded entries until at most `max_entries`
    /// remain, returning how many this call dropped.
    fn evict_to(&mut self, max_entries: usize) -> u64 {
        let mut dropped = 0u64;
        while self.entries.len() > max_entries {
            let (_, placeholder) = self
                .by_recency
                .pop_first()
                .expect("recency index tracks every retained entry");
            self.entries.remove(&placeholder);
            dropped += 1;
        }
        self.evicted += dropped;
        dropped
    }
}

impl fmt::Debug for BoundedMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedMapping")
            .field(
                "entries",
                &format_args!("<redacted: {} entrie(s)>", self.entries.len()),
            )
            .field("evicted", &self.evicted)
            .finish()
    }
}

/// Thread-safe live reverse-mapping store for long-running transports.
///
/// A management API and the proxy wire path share one store for their lifetime,
/// recording every mapping produced by either transport. This lets a response
/// detokenize placeholders minted by the current request or by the co-running
/// hook endpoint while keeping the secret-bearing mapping process-local.
///
/// # Bounded retention (issue #54)
///
/// Hook traffic is untrusted, so an unbounded process-lifetime store would let
/// a client flood unique secret-shaped values until memory is exhausted.
/// Retention is therefore capped ([`DEFAULT_MAX_ENTRIES`][Self::DEFAULT_MAX_ENTRIES]
/// entries unless overridden via [`with_max_entries`][Self::with_max_entries]);
/// past the cap, [`record`][Self::record] evicts least-recently-recorded
/// entries and surfaces the pressure via `tracing` and the
/// [`evicted`][Self::evicted] counter rather than dropping silently.
///
/// Why least-recently-**recorded** eviction is detokenization-safe in
/// practice: minting is a pure function of `(salt, secret)` (see the module
/// docs), so when an evicted secret transits either transport again the
/// byte-identical entry is simply re-recorded. Agent clients resend the full
/// conversation every turn and the wire path records before the upstream leg,
/// so every mapping still backing the ongoing conversation has its recency
/// refreshed each request. Hook-minted mappings are the long-lived case — the
/// placeholder replaces the secret *inside* the conversation, so the secret
/// never recurs to refresh it — which is why the cap is set orders of
/// magnitude above any legitimate session's distinct-secret count. Only an
/// adversarial flood reaches the cap, and then bounded memory (with loud
/// eviction telemetry) is preferred over process exhaustion, accepting that a
/// flooded-out placeholder echoed in a later response would pass through
/// unreversed.
pub struct MappingStore {
    inner: Mutex<BoundedMapping>,
    max_entries: usize,
}

impl Default for MappingStore {
    fn default() -> Self {
        Self::with_max_entries(Self::DEFAULT_MAX_ENTRIES)
    }
}

impl MappingStore {
    /// Default retention cap. Legitimate sessions hold tens to hundreds of
    /// distinct detected secrets; 8192 leaves ample headroom while bounding
    /// worst-case memory for a store fed by untrusted hook traffic.
    pub const DEFAULT_MAX_ENTRIES: usize = 8192;

    /// Create an empty live store with the default retention cap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty live store retaining at most `max_entries` mappings.
    ///
    /// **Panics** if `max_entries` is zero — a store that can retain nothing
    /// would silently break all detokenization.
    pub fn with_max_entries(max_entries: usize) -> Self {
        assert!(max_entries > 0, "mapping store capacity must not be zero");
        Self {
            inner: Mutex::new(BoundedMapping::default()),
            max_entries,
        }
    }

    /// Add all substitutions from one redaction verdict, refreshing recency
    /// for placeholders already retained and evicting least-recently-recorded
    /// entries if the cap is exceeded.
    pub fn record(&self, mapping: Mapping) {
        let mut inner = self
            .inner
            .lock()
            .expect("tokenization mapping store poisoned");
        for (placeholder, secret) in mapping.inner {
            inner.insert(placeholder, secret);
        }
        let dropped = inner.evict_to(self.max_entries);
        if dropped > 0 {
            tracing::warn!(
                evicted = dropped,
                evicted_total = inner.evicted,
                max_entries = self.max_entries,
                "mapping store over capacity; dropped least-recently-recorded mappings — their placeholders, if echoed in a later response, will no longer detokenize"
            );
        }
    }

    /// Take a point-in-time copy of the live mapping.
    ///
    /// Consumers snapshot under the mutex so no lock is held across await points
    /// or while a streaming response is being polled.
    pub fn snapshot(&self) -> Mapping {
        let inner = self
            .inner
            .lock()
            .expect("tokenization mapping store poisoned");
        Mapping {
            inner: inner
                .entries
                .iter()
                .map(|(placeholder, entry)| (placeholder.clone(), entry.secret.clone()))
                .collect(),
        }
    }

    /// Number of distinct placeholder mappings currently retained.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("tokenization mapping store poisoned")
            .entries
            .len()
    }

    /// Whether no substitutions have been retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total mappings evicted over this store's lifetime — the retention
    /// pressure metric paired with the `tracing` warnings from
    /// [`record`][Self::record]. Nonzero means hook/wire traffic minted more
    /// distinct secrets than the cap retains.
    pub fn evicted(&self) -> u64 {
        self.inner
            .lock()
            .expect("tokenization mapping store poisoned")
            .evicted
    }
}

impl fmt::Debug for MappingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappingStore")
            .field("max_entries", &self.max_entries)
            .field("inner", &self.inner)
            .finish()
    }
}

pub mod streaming;
pub use streaming::{StreamingDetokenizer, detokenize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_store_snapshot_is_a_point_in_time_clone() {
        let store = MappingStore::new();
        let mut first = Mapping::new();
        first.insert("<<hs:first>>", "sk-first");
        store.record(first);

        let snapshot = store.snapshot();
        let mut second = Mapping::new();
        second.insert("<<hs:second>>", "sk-second");
        store.record(second);

        assert_eq!(snapshot.get("<<hs:first>>"), Some("sk-first"));
        assert_eq!(snapshot.get("<<hs:second>>"), None);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn mapping_store_evicts_least_recently_recorded_beyond_capacity() {
        let store = MappingStore::with_max_entries(2);
        for (placeholder, secret) in [
            ("<<hs:aaaa>>", "sk-a"),
            ("<<hs:bbbb>>", "sk-b"),
            ("<<hs:cccc>>", "sk-c"),
        ] {
            let mut mapping = Mapping::new();
            mapping.insert(placeholder, secret);
            store.record(mapping);
        }
        assert_eq!(store.len(), 2);
        assert_eq!(store.evicted(), 1);
        let snapshot = store.snapshot();
        assert_eq!(snapshot.get("<<hs:aaaa>>"), None);
        assert_eq!(snapshot.get("<<hs:bbbb>>"), Some("sk-b"));
        assert_eq!(snapshot.get("<<hs:cccc>>"), Some("sk-c"));
    }

    #[test]
    fn mapping_store_re_recording_refreshes_eviction_order() {
        // Agent clients resend the whole conversation every turn, so the wire
        // path re-records every mapping still backing it. Re-recording must
        // refresh recency, or an in-use mapping could be evicted ahead of a
        // genuinely idle one.
        let store = MappingStore::with_max_entries(2);
        let record_one = |placeholder: &str, secret: &str| {
            let mut mapping = Mapping::new();
            mapping.insert(placeholder, secret);
            store.record(mapping);
        };
        record_one("<<hs:aaaa>>", "sk-a");
        record_one("<<hs:bbbb>>", "sk-b");
        record_one("<<hs:aaaa>>", "sk-a"); // refresh: a is now newer than b
        record_one("<<hs:cccc>>", "sk-c"); // evicts b, not a
        let snapshot = store.snapshot();
        assert_eq!(snapshot.get("<<hs:aaaa>>"), Some("sk-a"));
        assert_eq!(snapshot.get("<<hs:bbbb>>"), None);
        assert_eq!(snapshot.get("<<hs:cccc>>"), Some("sk-c"));
        assert_eq!(store.evicted(), 1);
    }

    #[test]
    fn mapping_store_evicted_entry_is_restored_by_deterministic_re_record() {
        // The safety argument for bounding at all: minting is a pure function
        // of (salt, secret), so when an evicted secret transits again the
        // byte-identical placeholder→secret entry is re-recorded.
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-old"]);
        let placeholder = t.placeholder_for("sk-old").unwrap().to_string();
        let store = MappingStore::with_max_entries(1);

        let (_, mapping) = t.tokenize("value=sk-old");
        store.record(mapping);
        let mut flood = Mapping::new();
        flood.insert("<<hs:flood>>", "sk-flood");
        store.record(flood);
        assert_eq!(store.snapshot().get(&placeholder), None);

        let (_, mapping_again) = t.tokenize("value=sk-old");
        store.record(mapping_again);
        assert_eq!(store.snapshot().get(&placeholder), Some("sk-old"));
    }

    #[test]
    fn mapping_store_debug_redacts_retained_secrets() {
        let store = MappingStore::new();
        let mut mapping = Mapping::new();
        mapping.insert("<<hs:deadbeef>>", "sk-super-secret-value");
        store.record(mapping);
        let debug = format!("{store:?}");
        assert!(!debug.contains("sk-super-secret-value"));
    }

    #[test]
    #[should_panic(expected = "mapping store capacity must not be zero")]
    fn mapping_store_zero_capacity_panics() {
        let _ = MappingStore::with_max_entries(0);
    }

    #[test]
    fn happy_path_placeholders_match_sentinel_format() {
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["sk-secret-1", "sk-secret-2"]);
        assert_eq!(t.len(), 2);
        for (_, placeholder) in t.entries() {
            assert!(placeholder.starts_with(PLACEHOLDER_PREFIX));
            assert!(placeholder.ends_with(PLACEHOLDER_SUFFIX));
            assert_eq!(placeholder.len(), MAX_PLACEHOLDER_LEN);
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
        // Same secret, different salts → different placeholders. This is the
        // observable signature of the salt being an HMAC *key*: a non-keyed
        // hash of the secret alone would collide here, so this assertion is
        // what catches a regression to a forgeable (salt-independent) token.
        assert_ne!(placeholder_a, placeholder_b);
        // And the placeholder is stable under its own salt (not accidentally
        // salt-independent the other way): re-minting under salt-a reproduces
        // placeholder_a, so the difference above is genuinely salt-driven.
        let salt_a_again = SecretTokenizer::new(b"salt-a".to_vec(), vec!["sk-shared-secret"]);
        assert_eq!(
            placeholder_a,
            salt_a_again.placeholder_for("sk-shared-secret").unwrap()
        );
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

    #[test]
    fn try_new_rejects_an_empty_salt_but_accepts_a_non_empty_one() {
        // Regression (coderabbit review of PR #15): an empty HMAC key makes
        // placeholders publicly reproducible for a known secret, defeating
        // FR-007 unforgeability. Construction must fail closed.
        assert_eq!(
            SecretTokenizer::try_new(Vec::<u8>::new(), vec!["sk-secret-1"]).unwrap_err(),
            SecretTokenizerError::EmptySalt
        );
        assert!(SecretTokenizer::try_new(b"fixed-salt".to_vec(), vec!["sk-secret-1"]).is_ok());
    }

    #[test]
    #[should_panic(expected = "session salt must not be empty")]
    fn new_panics_on_empty_salt() {
        let _ = SecretTokenizer::new(Vec::<u8>::new(), vec!["sk-secret-1"]);
    }

    #[test]
    fn empty_secret_is_skipped_and_never_splices_placeholders() {
        // Regression (gemini-code-assist review of PR #15): an empty secret
        // would register an empty aho-corasick pattern that matches at every
        // position. It must be dropped at construction, and the surrounding
        // real secrets must still tokenize normally.
        let t = SecretTokenizer::new(b"fixed-salt".to_vec(), vec!["", "sk-real", ""]);
        assert_eq!(t.len(), 1);
        assert_eq!(t.placeholder_for(""), None);

        let (out, mapping) = t.tokenize("plain text with sk-real inside");
        // No placeholder was spliced between every byte: the only substitution
        // is the genuine secret, so the non-secret text is untouched.
        assert!(out.starts_with("plain text with "));
        assert!(out.ends_with(" inside"));
        assert!(!out.contains("sk-real"));
        assert_eq!(mapping.len(), 1);
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
