//! Honmoon core: policy model, verdicts, and protocol facts.
//!
//! This crate is intentionally transport-agnostic. The proxy crate feeds it
//! protocol [`Facts`] and receives a [`Verdict`].

use serde::{Deserialize, Serialize};

/// The decision the policy engine returns for a given request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Let the request through.
    Allow,
    /// Block the request.
    Deny,
    /// Hold the request until a human approves it.
    Pause,
}

/// A declarative policy document (`policies/*.yaml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub egress: Egress,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Domain allow/deny lists — the common-case egress filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Egress {
    /// Verdict when no allow/deny entry matches.
    #[serde(default = "default_deny")]
    pub default: Verdict,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for Egress {
    fn default() -> Self {
        Self { default: Verdict::Deny, allow: Vec::new(), deny: Vec::new() }
    }
}

fn default_deny() -> Verdict {
    Verdict::Deny
}

/// A protocol-aware rule evaluated against [`Facts`] via a CEL condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub endpoint: String,
    /// CEL expression over protocol facts, e.g. `"sql.verb == 'DROP'"`.
    pub condition: String,
    pub verdict: Verdict,
}

/// Protocol facts extracted at the wire level (without decryption inspection).
///
/// Populated incrementally by protocol parsers in `honmoon-proxy`.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub domain: Option<String>,
    // TODO: http / sql / k8s fact sub-structs as parsers land.
}

impl Policy {
    /// Parse a policy from YAML.
    pub fn from_yaml(src: &str) -> Result<Self, Error> {
        serde_yaml::from_str(src).map_err(Error::Parse)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse policy: {0}")]
    Parse(#[from] serde_yaml::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_egress_policy() {
        let policy = Policy::from_yaml(
            r#"
version: 1
egress:
  default: deny
  allow:
    - github.com
  deny:
    - "*.internal.corp"
"#,
        )
        .expect("valid policy");

        assert_eq!(policy.version, 1);
        assert_eq!(policy.egress.default, Verdict::Deny);
        assert_eq!(policy.egress.allow, vec!["github.com"]);
    }

    #[test]
    fn parses_protocol_rule() {
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: pause
"#,
        )
        .expect("valid policy");

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].verdict, Verdict::Pause);
    }
}
