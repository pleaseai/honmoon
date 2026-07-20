//! Combined secret + PII redaction — the join between detection
//! ([`crate::secret_detect`], [`crate::pii`]) and the reversible tokenizer
//! ([`crate::SecretTokenizer`]).
//!
//! This is the single engine behind the Claude Code plugin's hooks (issue #19)
//! and the gateway-direct HTTP wire transport. It stays pure logic (no I/O):
//! the caller supplies the text and a session salt, and gets back the redacted
//! text plus what was found. Because the tokenizer mints
//! deterministic, byte-stable placeholders for a given `(salt, secret)`,
//! re-redacting resent conversation history is byte-identical across turns
//! (issue #20) — the caller need do nothing extra to keep a provider's
//! prompt-cache prefix stable.
//!
//! The plugin path does not itself reverse substitutions, but the management
//! hook transport records the returned [`Mapping`] in the same live store as
//! the proxy wire path. Identity-encoded proxy responses can therefore restore
//! placeholders minted by either transport within one gateway process.

use std::collections::BTreeSet;

use crate::pii::{self, PiiSpan};
use crate::secret_detect::detect_secrets;
use crate::secret_tokenizer::{Mapping, SecretTokenizer};

/// Default PII severity floor for redaction: MEDIUM. Bare IPv4 (LOW) is left
/// alone to cut noise; RRN / card / email / phone (MEDIUM+) are redacted.
/// Secrets are always redacted regardless of this floor.
pub const DEFAULT_MIN_PII_SEVERITY: i64 = 2;

/// The result of a [`redact`] call.
///
/// `text` is the redacted output (equal to the input when nothing was found).
/// `secret_labels` / `pii_labels` are the unique, sorted detector labels that
/// fired (PII labels are only those at or above the requested severity floor).
/// `max_pii_severity` is the highest severity among redacted PII (0 if none).
/// `mapping` is the placeholder→secret mapping actually substituted.
#[derive(Debug)]
pub struct RedactionOutcome {
    pub text: String,
    pub redacted: bool,
    pub secret_labels: Vec<String>,
    pub pii_labels: Vec<String>,
    pub max_pii_severity: i64,
    pub mapping: Mapping,
}

impl RedactionOutcome {
    /// Whether any secret (as opposed to PII) surface was detected.
    pub fn has_secret(&self) -> bool {
        !self.secret_labels.is_empty()
    }

    /// All fired labels (secrets then PII), unique and each already sorted.
    pub fn labels(&self) -> Vec<String> {
        let mut all = self.secret_labels.clone();
        all.extend(self.pii_labels.iter().cloned());
        all
    }
}

/// Detect secrets + PII (at or above `min_pii_severity`) in `text` and replace
/// every detected surface with its stable placeholder.
///
/// `salt` is the HMAC key behind placeholder unforgeability. When at least one
/// surface is detected this constructs a [`SecretTokenizer::new`], which
/// **requires a non-empty salt and panics on an empty one** — an empty salt is a
/// caller programming error, not a recoverable input, so it panics rather than
/// silently minting forgeable tokens or failing open. (Text with nothing to
/// redact returns early and never reaches the tokenizer, so an empty salt does
/// not panic in that case — callers must still always pass a real salt.)
pub fn redact(text: &str, salt: &[u8], min_pii_severity: i64) -> RedactionOutcome {
    let pii_spans = pii::detect_spans(text);
    redact_with_spans(text, salt, min_pii_severity, &pii_spans)
}

/// Redact secrets and the supplied precomputed PII spans.
///
/// `pii_spans` must have been detected from `text`. This additive entry point is
/// useful when a caller needs both PII policy facts and redaction for the same
/// request, avoiding a second full PII detector pass.
pub fn redact_with_spans(
    text: &str,
    salt: &[u8],
    min_pii_severity: i64,
    pii_spans: &[PiiSpan],
) -> RedactionOutcome {
    // Collect surfaces to register. Secrets go first: registration order is the
    // tokenizer's tie-break for equal-length leftmost-longest matches, and a
    // secret should win over a coincidentally-overlapping PII span.
    let mut surfaces: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut secret_labels: BTreeSet<String> = BTreeSet::new();

    for finding in detect_secrets(text) {
        secret_labels.insert(finding.label);
        if seen.insert(finding.text.clone()) {
            surfaces.push(finding.text);
        }
    }

    let mut pii_labels: BTreeSet<String> = BTreeSet::new();
    let mut max_pii_severity = 0i64;
    for span in pii_spans {
        let severity = pii::severity_for_label(&span.label);
        if severity < min_pii_severity {
            continue;
        }
        pii_labels.insert(span.label.clone());
        max_pii_severity = max_pii_severity.max(severity);
        if seen.insert(span.text.clone()) {
            surfaces.push(span.text.clone());
        }
    }

    if surfaces.is_empty() {
        return RedactionOutcome {
            text: text.to_string(),
            redacted: false,
            secret_labels: secret_labels.into_iter().collect(),
            pii_labels: pii_labels.into_iter().collect(),
            max_pii_severity,
            mapping: Mapping::new(),
        };
    }

    let tokenizer = SecretTokenizer::new(salt.to_vec(), surfaces);
    let (redacted_text, mapping) = tokenizer.tokenize(text);

    RedactionOutcome {
        text: redacted_text,
        redacted: !mapping.is_empty(),
        secret_labels: secret_labels.into_iter().collect(),
        pii_labels: pii_labels.into_iter().collect(),
        max_pii_severity,
        mapping,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX};

    const SALT: &[u8] = b"redact-test-salt";
    const RRN: &str = "670125-1230644"; // valid checksum (mirrors pii.rs tests)
    const ANTHROPIC_KEY: &str = "sk-ant-api03-cache-stable-abcDEF123456";

    #[test]
    fn redacts_a_valid_rrn() {
        let out = redact(
            &format!("제 주민번호는 {RRN} 입니다"),
            SALT,
            DEFAULT_MIN_PII_SEVERITY,
        );
        assert!(out.redacted);
        assert!(!out.text.contains(RRN));
        assert!(out.text.contains(PLACEHOLDER_PREFIX));
        assert_eq!(out.pii_labels, vec!["RRN"]);
        assert!(!out.has_secret());
    }

    #[test]
    fn redacts_an_api_key() {
        let out = redact(
            &format!("deploy with {ANTHROPIC_KEY} now"),
            SALT,
            DEFAULT_MIN_PII_SEVERITY,
        );
        assert!(out.redacted);
        assert!(out.has_secret());
        assert!(!out.text.contains(ANTHROPIC_KEY));
        assert_eq!(out.secret_labels, vec!["ANTHROPIC_KEY"]);
    }

    #[test]
    fn redacts_secret_and_pii_together() {
        let out = redact(
            &format!("key {ANTHROPIC_KEY} for user rrn {RRN}"),
            SALT,
            DEFAULT_MIN_PII_SEVERITY,
        );
        assert!(out.redacted);
        assert!(!out.text.contains(ANTHROPIC_KEY));
        assert!(!out.text.contains(RRN));
        assert!(out.has_secret());
        assert_eq!(out.pii_labels, vec!["RRN"]);
    }

    #[test]
    fn passthrough_when_nothing_found() {
        let out = redact("just an ordinary sentence", SALT, DEFAULT_MIN_PII_SEVERITY);
        assert!(!out.redacted);
        assert_eq!(out.text, "just an ordinary sentence");
        assert!(out.mapping.is_empty());
        assert!(out.labels().is_empty());
    }

    #[test]
    fn is_byte_deterministic_across_calls() {
        // Issue #20: the same bytes under the same salt redact identically, so
        // re-redacting resent history preserves a provider's prompt-cache prefix.
        let text = format!("{ANTHROPIC_KEY} and {RRN}");
        let a = redact(&text, SALT, DEFAULT_MIN_PII_SEVERITY);
        let b = redact(&text, SALT, DEFAULT_MIN_PII_SEVERITY);
        assert_eq!(a.text, b.text);
    }

    #[test]
    fn min_severity_gate_skips_low_severity_ip_by_default() {
        // A bare IPv4 is LOW severity: not redacted at the MEDIUM default...
        let default = redact("connect to 10.0.0.1 please", SALT, DEFAULT_MIN_PII_SEVERITY);
        assert!(!default.redacted);
        assert!(default.text.contains("10.0.0.1"));
        // ...but redacted when the floor is lowered to LOW.
        let low = redact("connect to 10.0.0.1 please", SALT, 1);
        assert!(low.redacted);
        assert!(!low.text.contains("10.0.0.1"));
        assert_eq!(low.pii_labels, vec!["IP"]);
    }

    #[test]
    fn secrets_are_redacted_regardless_of_pii_floor() {
        // Even with the PII floor above HIGH, a secret is still redacted.
        let out = redact(&format!("key {ANTHROPIC_KEY}"), SALT, 99);
        assert!(out.redacted);
        assert!(out.has_secret());
        assert!(!out.text.contains(ANTHROPIC_KEY));
    }

    #[test]
    fn redacts_a_pem_private_key_block() {
        // A multi-line PEM block is captured header-through-footer and replaced
        // wholesale, so no fragment of the block survives.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                   MIIBOgIBAAJBAKjabc123DEF456ghiJKLmno\n\
                   -----END RSA PRIVATE KEY-----";
        let out = redact(
            &format!("here is the key:\n{pem}\n"),
            SALT,
            DEFAULT_MIN_PII_SEVERITY,
        );
        assert!(out.redacted);
        assert!(out.has_secret());
        assert_eq!(out.secret_labels, vec!["PRIVATE_KEY"]);
        assert!(!out.text.contains("PRIVATE KEY"));
        assert!(out.text.contains(PLACEHOLDER_PREFIX));
        // Surrounding prose is preserved.
        assert!(out.text.contains("here is the key:"));
    }

    #[test]
    fn redacts_a_keyword_anchored_generic_secret() {
        // Only the high-entropy value (not the `api_key = ` anchor) is replaced.
        let secret = "aB3xK9zQ1mP7wR2t";
        let out = redact(
            &format!("api_key = \"{secret}\""),
            SALT,
            DEFAULT_MIN_PII_SEVERITY,
        );
        assert!(out.redacted);
        assert!(out.has_secret());
        assert_eq!(out.secret_labels, vec!["GENERIC_SECRET"]);
        assert!(!out.text.contains(secret));
        assert!(out.text.starts_with("api_key = \""));
    }

    #[test]
    fn mapping_reverses_each_placeholder_to_its_secret() {
        // The returned mapping is the placeholder→secret substitution actually
        // applied — every placeholder in the output must reverse to its surface.
        let out = redact(
            &format!("key {ANTHROPIC_KEY} rrn {RRN}"),
            SALT,
            DEFAULT_MIN_PII_SEVERITY,
        );
        assert!(out.redacted);
        assert_eq!(out.mapping.len(), 2, "one entry per unique surface");
        let recovered: Vec<&str> = placeholders(&out.text)
            .iter()
            .filter_map(|p| out.mapping.get(p))
            .collect();
        assert!(
            recovered.contains(&ANTHROPIC_KEY),
            "mapping recovers the API key"
        );
        assert!(recovered.contains(&RRN), "mapping recovers the RRN");
    }

    /// Extract every `<<hs:…>>` placeholder occurring in `text`, in order.
    fn placeholders(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find(PLACEHOLDER_PREFIX) {
            let after = &rest[start..];
            match after.find(PLACEHOLDER_SUFFIX) {
                Some(end) => {
                    let end = end + PLACEHOLDER_SUFFIX.len();
                    out.push(after[..end].to_string());
                    rest = &after[end..];
                }
                None => break,
            }
        }
        out
    }
}
