//! Tier-1 deterministic secret detection: regex + prefix / entropy validation.
//!
//! Companion to [`crate::pii`]. Where `pii.rs` finds *personal* data, this
//! finds *machine credentials* — API keys, tokens, private keys — by their
//! structural shape. It shares the same precision-first philosophy: a
//! permissive regex proposes a candidate and a `validate` gate confirms it, so
//! false positives (which would redact legitimate text) stay near zero. The
//! detected surface strings feed [`crate::redact::redact`], which registers
//! them into a [`crate::SecretTokenizer`] and substitutes every occurrence.
//!
//! Unlike `pii.rs`'s [`crate::pii::PiiSpan`], [`SecretFinding`] deliberately
//! does **not** derive `Serialize`/`Deserialize`: it carries live secret bytes
//! in `text`, so it follows the secret-bearing convention of
//! [`crate::SecretTokenizer`]/[`crate::Mapping`] (NFR-005) rather than the
//! derived-facts convention of the PII spans.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

/// A located secret finding: the canonical `label` plus the exact matched
/// `text` (surface form). Offsets are intentionally omitted — the redactor
/// registers `text` into a `SecretTokenizer`, which then locates every
/// occurrence itself (leftmost-longest), so a start/end here would be
/// redundant and would only invite drift from the tokenizer's own matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    /// Canonical detector label, e.g. `"ANTHROPIC_KEY"`.
    pub label: String,
    /// The exact secret surface to redact.
    pub text: String,
}

struct Detector {
    /// Canonical label reported on a match.
    label: &'static str,
    /// Candidate matcher. Kept permissive; `validate` is the real gate.
    re: &'static LazyLock<Regex>,
    /// Which capture group holds the secret surface (0 = whole match). The
    /// keyword-anchored generic detector captures only the *value*, not the
    /// `key =` prefix, so it does not redact the surrounding assignment text.
    capture: usize,
    /// Confirms a candidate surface. High-signal prefixes (`AKIA…`, `sk-ant-…`)
    /// use [`always`]; the generic detector gates on entropy + a placeholder
    /// denylist.
    validate: fn(&str) -> bool,
}

// The prefix detectors below open with `(?-u:\b)` (ASCII word boundary) for the
// same reason as `pii.rs`: credentials are often written flush against non-ASCII
// text, and a Unicode `\b` treats CJK as a word char and never fires at the
// seam. (`PRIVATE_KEY_RE` and `GENERIC_ASSIGN_RE` further below do not — one is a
// structural block match, the other keyword-anchored.)
//
// Anthropic keys: `sk-ant-` then a long body that may contain `-`/`_`.
static ANTHROPIC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)sk-ant-[A-Za-z0-9_-]{20,}").unwrap());
// OpenAI keys: `sk-` or `sk-proj-` then a long body. Modern `sk-proj-…` keys
// embed `_`/`-` separators, so the body class must include them or the match
// would stop at the first separator and leave the rest of the key in plaintext
// (or, if the leading segment is <20 chars, miss the key entirely). The
// `is_openai_key` gate keeps this disjoint from the Anthropic `sk-ant-` form,
// which now shares the same body class.
static OPENAI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)sk-(?:proj-)?[A-Za-z0-9_-]{20,}").unwrap());
// AWS access key id: `AKIA` (long-term) or `ASIA` (temporary/STS) + exactly 16
// upper/digits (20 total). Trailing boundary rejects a longer alnum blob that
// merely starts with the prefix.
static AWS_AKID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)(?:AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)").unwrap());
// GitHub tokens: classic `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + >=36 alnum, or
// fine-grained `github_pat_` + a long alnum/underscore body.
static GITHUB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})").unwrap()
});
// Slack tokens: bot/user/etc. `xoxb-`/`xoxa-`/`xoxp-`/`xoxr-`/`xoxs-`, plus
// app-level `xapp-` and workflow `xwfp-` tokens + a hyphenated body.
static SLACK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)(?:xox[baprs]-|xapp-|xwfp-)[A-Za-z0-9-]{10,}").unwrap());
// Google API keys: `AIza` + exactly 35 of `[A-Za-z0-9_-]`.
static GOOGLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)AIza[0-9A-Za-z_-]{35}(?-u:\b)").unwrap());
// PEM private key block: header through the matching footer, across newlines.
static PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .unwrap()
});
// Keyword-anchored assignment: `api_key = "<value>"` and friends. Group 1 is
// the value only; `validate` (entropy + denylist) keeps precision high — this
// is the one detector without a strong structural prefix.
static GENERIC_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./+]{16,})"#,
    )
    .unwrap()
});

static DETECTORS: &[Detector] = &[
    Detector {
        label: "ANTHROPIC_KEY",
        re: &ANTHROPIC_RE,
        capture: 0,
        validate: always,
    },
    Detector {
        label: "OPENAI_KEY",
        re: &OPENAI_RE,
        capture: 0,
        validate: is_openai_key,
    },
    Detector {
        label: "AWS_ACCESS_KEY_ID",
        re: &AWS_AKID_RE,
        capture: 0,
        validate: always,
    },
    Detector {
        label: "GITHUB_TOKEN",
        re: &GITHUB_RE,
        capture: 0,
        validate: always,
    },
    Detector {
        label: "SLACK_TOKEN",
        re: &SLACK_RE,
        capture: 0,
        validate: always,
    },
    Detector {
        label: "GOOGLE_API_KEY",
        re: &GOOGLE_RE,
        capture: 0,
        validate: always,
    },
    Detector {
        label: "PRIVATE_KEY",
        re: &PRIVATE_KEY_RE,
        capture: 0,
        validate: always,
    },
    Detector {
        label: "GENERIC_SECRET",
        re: &GENERIC_ASSIGN_RE,
        capture: 1,
        validate: is_plausible_secret_value,
    },
];

/// Scan `payload` for secret surfaces. Findings are reported per detector and
/// per occurrence (not deduplicated) — the redactor deduplicates by surface
/// when it registers them into a [`crate::SecretTokenizer`].
pub fn detect_secrets(payload: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    for det in DETECTORS {
        for caps in det.re.captures_iter(payload) {
            let Some(m) = caps.get(det.capture) else {
                continue;
            };
            let surface = m.as_str();
            if (det.validate)(surface) {
                out.push(SecretFinding {
                    label: det.label.to_string(),
                    text: surface.to_string(),
                });
            }
        }
    }
    out
}

fn always(_: &str) -> bool {
    true
}

// Reject the Anthropic form so an `sk-ant-…XXXX` (no interior hyphen after
// `ant`) is not double-labelled as OpenAI. The regex already makes the two
// largely disjoint; this is belt-and-suspenders.
fn is_openai_key(s: &str) -> bool {
    !s.starts_with("sk-ant-")
}

/// Common non-secret filler values that a keyword anchor would otherwise catch
/// (`api_key = "your_api_key_here"`). Matched case-insensitively as substrings.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "example",
    "your",
    "changeme",
    "change-me",
    "placeholder",
    "redacted",
    "xxxx",
    "todo",
    "none",
    "null",
    "test",
    "sample",
    "dummy",
    "fake",
];

// Gate for the keyword-anchored generic detector. The regex guarantees length
// >= 16; this rejects obvious placeholders and low-entropy / single-class
// values so ordinary config (`token: enabled`, `password = your_password`) is
// not redacted.
fn is_plausible_secret_value(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if PLACEHOLDER_MARKERS.iter().any(|p| lower.contains(p)) {
        return false;
    }
    // Require at least two of {lowercase, uppercase, digit} — defeats dictionary
    // words and single-run fillers ("aaaaaaaaaaaaaaaa", "ABCDEFGHIJKLMNOP") while
    // still accepting uppercase-only credentials that carry digits (base32 TOTP
    // secrets, uppercase hex tokens), which a lowercase-mandatory rule would miss.
    let classes = u8::from(s.chars().any(|c| c.is_ascii_lowercase()))
        + u8::from(s.chars().any(|c| c.is_ascii_uppercase()))
        + u8::from(s.chars().any(|c| c.is_ascii_digit()));
    classes >= 2 && shannon_bits_per_char(s) >= 3.0
}

// Shannon entropy in bits per character. Truly random base62 approaches its
// per-length ceiling; repetitive or dictionary strings fall well below the
// 3.0-bit gate above.
fn shannon_bits_per_char(s: &str) -> f64 {
    let n = s.chars().count();
    if n == 0 {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let n = n as f64;
    counts
        .values()
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(s: &str) -> Vec<String> {
        let mut ls: Vec<String> = detect_secrets(s).into_iter().map(|f| f.label).collect();
        ls.sort();
        ls.dedup();
        ls
    }

    fn only_finding(s: &str) -> SecretFinding {
        let mut fs = detect_secrets(s);
        assert_eq!(fs.len(), 1, "expected exactly one finding in {s:?}: {fs:?}");
        fs.pop().unwrap()
    }

    #[test]
    fn detects_anthropic_key() {
        let f = only_finding("deploy with key sk-ant-api03-cache-stable-abcDEF123456 now");
        assert_eq!(f.label, "ANTHROPIC_KEY");
        assert_eq!(f.text, "sk-ant-api03-cache-stable-abcDEF123456");
    }

    #[test]
    fn detects_openai_key_but_not_as_anthropic() {
        let f = only_finding("OPENAI_API_KEY was sk-abcDEF0123456789ghIJKLmnop rotated");
        assert_eq!(f.label, "OPENAI_KEY");
    }

    #[test]
    fn openai_proj_key_variant() {
        let f = only_finding("key sk-proj-abcDEF0123456789ghIJKLmnop end");
        assert_eq!(f.label, "OPENAI_KEY");
    }

    #[test]
    fn openai_proj_key_with_separators_is_captured_whole() {
        // Modern sk-proj- keys embed `_`/`-` separators. The whole key must be
        // captured (regression for the body class excluding separators, which
        // truncated the match and left the tail in plaintext).
        let key = "sk-proj-Ab1_Cd2-Ef3Gh4_Ij5Kl6-Mn7Op8Qr9St0";
        let f = only_finding(&format!("OPENAI_KEY={key}"));
        assert_eq!(f.label, "OPENAI_KEY");
        assert_eq!(f.text, key);
    }

    #[test]
    fn detects_aws_access_key_id() {
        // Canonical AWS docs example — AKIA + exactly 16 = 20 chars.
        assert_eq!(labels("AKIAIOSFODNN7EXAMPLE"), vec!["AWS_ACCESS_KEY_ID"]);
    }

    #[test]
    fn detects_aws_temporary_access_key_id() {
        // STS / temporary credentials use the `ASIA` prefix (same 20-char shape)
        // and must be redacted just like long-term `AKIA` ids.
        assert_eq!(labels("ASIAIOSFODNN7EXAMPLE"), vec!["AWS_ACCESS_KEY_ID"]);
    }

    #[test]
    fn aws_key_rejects_overlong_alnum_blob() {
        // A 30-char run that merely starts with AKIA is not a 20-char key id.
        assert!(detect_secrets("AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ0123").is_empty());
    }

    #[test]
    fn detects_github_token() {
        let tok = format!("ghp_{}", "a1B2c3D4e5".repeat(4)); // 40 body chars
        // Neutral context (no secret keyword) so only the structural GitHub
        // detector fires — a `token=` prefix would also (correctly) trip the
        // generic keyword-anchored detector.
        assert_eq!(
            labels(&format!("credential {tok} present")),
            vec!["GITHUB_TOKEN"]
        );
    }

    #[test]
    fn detects_fine_grained_github_pat() {
        // Fine-grained PATs use the `github_pat_` prefix with a long
        // alnum/underscore body — a shape the classic `ghp_` matcher misses.
        let tok = format!("github_pat_11ABCDEFG0{}", "aB3xK9zQ1m".repeat(7));
        assert_eq!(
            labels(&format!("credential {tok} present")),
            vec!["GITHUB_TOKEN"]
        );
    }

    #[test]
    fn detects_slack_token() {
        assert_eq!(
            labels("xoxb-123456789012-abcdEFGHijkl"),
            vec!["SLACK_TOKEN"]
        );
    }

    #[test]
    fn detects_slack_app_and_workflow_tokens() {
        // App-level (`xapp-`) and workflow (`xwfp-`) tokens are documented Slack
        // credential formats alongside the `xox?-` family.
        assert_eq!(
            labels("xapp-1-A1B2C3D4E5-9876543210-abcdEFGH"),
            vec!["SLACK_TOKEN"]
        );
        assert_eq!(labels("xwfp-1-A1B2C3D4E5F6G7H8I9"), vec!["SLACK_TOKEN"]);
    }

    #[test]
    fn detects_google_api_key() {
        let key = format!("AIza{}", "a1B2c3D4e5".repeat(3) + "abcde"); // 35 chars
        assert_eq!(labels(&key), vec!["GOOGLE_API_KEY"]);
    }

    #[test]
    fn detects_pem_private_key_block() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\nDEF456==\n-----END RSA PRIVATE KEY-----";
        let f = only_finding(pem);
        assert_eq!(f.label, "PRIVATE_KEY");
        assert_eq!(f.text, pem);
    }

    #[test]
    fn detects_generic_keyword_anchored_secret() {
        // High-entropy, mixed-class value behind a keyword anchor.
        let f = only_finding(r#"api_key = "aB3xK9zQ1mP7wR2t""#);
        assert_eq!(f.label, "GENERIC_SECRET");
        assert_eq!(f.text, "aB3xK9zQ1mP7wR2t");
    }

    #[test]
    fn generic_accepts_uppercase_only_secret_with_digits() {
        // Uppercase base32 / hex credentials (no lowercase) must still be caught
        // behind a keyword anchor — the gate requires 2 of 3 char classes, not a
        // lowercase char specifically.
        let f = only_finding("secret = JBSWY3DPEHPK3PXPGEZDG");
        assert_eq!(f.label, "GENERIC_SECRET");
        assert_eq!(f.text, "JBSWY3DPEHPK3PXPGEZDG");
    }

    #[test]
    fn generic_rejects_placeholders_and_low_entropy() {
        // Placeholder fillers and single-class / low-entropy values must not
        // be flagged even though a keyword precedes them.
        assert!(detect_secrets(r#"api_key = "your_api_key_here_xxxx""#).is_empty());
        assert!(detect_secrets(r#"password = "changeme_now_please""#).is_empty());
        assert!(detect_secrets("token = aaaaaaaaaaaaaaaaaaaa").is_empty());
        assert!(detect_secrets("secret: example_value_placeholder").is_empty());
        // Single-class uppercase-only word (no digits) stays rejected.
        assert!(detect_secrets("token = ABCDEFGHIJKLMNOPQRST").is_empty());
    }

    #[test]
    fn hard_negatives_are_not_flagged() {
        // UUID, git sha, ordinary prose, and a bare high-entropy blob with no
        // keyword anchor must all produce nothing.
        assert!(detect_secrets("3f9a1c2b4d5e6f708192a3b4c5d6e7f8").is_empty());
        assert!(detect_secrets("550e8400-e29b-41d4-a716-446655440000").is_empty());
        assert!(detect_secrets("the quick brown fox jumps over the lazy dog").is_empty());
        assert!(detect_secrets("commit 9ad9e82 test core guarantee").is_empty());
    }

    #[test]
    fn reports_every_occurrence_for_the_redactor_to_dedup() {
        let key = "sk-ant-api03-cache-stable-abcDEF123456";
        let fs = detect_secrets(&format!("{key} and again {key}"));
        assert_eq!(fs.len(), 2);
        assert!(fs.iter().all(|f| f.text == key));
    }
}
