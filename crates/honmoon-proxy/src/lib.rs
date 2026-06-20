//! Honmoon wire-level proxy and protocol parsers.
//!
//! Accepts agent connections, extracts protocol [`Facts`](honmoon_core::Facts),
//! and applies the [`Policy`](honmoon_core::Policy) before forwarding upstream.

use honmoon_core::{Facts, Policy, Verdict};

pub mod gateway;

/// Evaluate a request's facts against a policy.
///
/// Placeholder logic: only egress domain matching is wired up for now.
/// CEL rule evaluation against protocol facts lands with the parsers.
pub fn evaluate(policy: &Policy, facts: &Facts) -> Verdict {
    if let Some(domain) = &facts.domain {
        if policy.egress.deny.iter().any(|p| matches_domain(p, domain)) {
            return Verdict::Deny;
        }
        if policy
            .egress
            .allow
            .iter()
            .any(|p| matches_domain(p, domain))
        {
            return Verdict::Allow;
        }
    }
    policy.egress.default
}

/// Match a domain against a pattern supporting a leading `*.` wildcard.
///
/// Matching is case-insensitive. Callers should pass an already-canonicalized
/// `domain` (lowercased, trailing dot stripped); the pattern is lowercased here
/// so policy authors need not worry about case.
fn matches_domain(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain == suffix || domain.ends_with(&format!(".{suffix}"))
    } else {
        pattern == domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(domain: &str) -> Facts {
        Facts {
            domain: Some(domain.to_string()),
        }
    }

    #[test]
    fn allows_listed_domain_denies_rest() {
        let policy =
            Policy::from_yaml("egress:\n  default: deny\n  allow:\n    - github.com\n").unwrap();

        assert_eq!(evaluate(&policy, &facts("github.com")), Verdict::Allow);
        assert_eq!(evaluate(&policy, &facts("evil.com")), Verdict::Deny);
    }

    #[test]
    fn pattern_matching_is_case_insensitive() {
        // Policy patterns may use any case; the (already-canonicalized) domain matches.
        assert!(matches_domain("GitHub.com", "github.com"));
        assert!(matches_domain(
            "*.GitHubUserContent.com",
            "raw.githubusercontent.com"
        ));
    }

    #[test]
    fn wildcard_matches_subdomains() {
        assert!(matches_domain(
            "*.githubusercontent.com",
            "raw.githubusercontent.com"
        ));
        assert!(matches_domain(
            "*.githubusercontent.com",
            "githubusercontent.com"
        ));
        assert!(!matches_domain(
            "*.githubusercontent.com",
            "evilgithubusercontent.com"
        ));
    }
}
