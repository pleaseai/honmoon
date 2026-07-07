//! Honmoon core: policy model, verdicts, and protocol facts.
//!
//! This crate is intentionally transport-agnostic. The proxy crate feeds it
//! protocol [`Facts`] and receives a [`Verdict`].

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod engine;
pub mod pii;
pub mod protocols;
pub mod secret_tokenizer;

pub use audit::{AuditDraft, AuditEvent, AuditLog, Decision, FactsSummary};
pub use engine::{Outcome, decide, decide_explained};
pub use pii::{PiiFacts, PiiSpan, detect_pii, detect_spans};

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
        Self {
            default: Verdict::Deny,
            allow: Vec::new(),
            deny: Vec::new(),
        }
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
/// Populated incrementally by protocol parsers in `honmoon-proxy` (see
/// [`crate::protocols`]). Sub-structs (`http`/`sql`/`k8s`) are exposed to CEL
/// rule conditions as variables of the same name, e.g. `sql.verb == 'DROP'`.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// Target domain (canonicalized: lowercased, no trailing dot).
    pub domain: Option<String>,
    /// Named endpoint this connection targets (matched against `Rule::endpoint`).
    pub endpoint: Option<String>,
    /// HTTP request facts (only fully populated once TLS is terminated).
    pub http: Option<HttpFacts>,
    /// SQL facts parsed from the wire (e.g. PostgreSQL simple query).
    pub sql: Option<SqlFacts>,
    /// Kubernetes API request facts.
    pub k8s: Option<K8sFacts>,
    /// Content-aware PII detection summary (Tier-1; see [`crate::pii`]).
    pub pii: Option<PiiFacts>,
}

/// HTTP request facts exposed to CEL as the `http` variable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpFacts {
    pub method: String,
    pub host: String,
    pub path: String,
    pub body_size: i64,
}

/// SQL facts exposed to CEL as the `sql` variable.
///
/// `verb` is the leading SQL keyword, uppercased (`SELECT`, `DROP`, `TRUNCATE`,
/// …). `table` is a best-effort primary table/relation name, lowercased.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SqlFacts {
    pub verb: String,
    pub table: String,
}

/// Kubernetes API request facts exposed to CEL as the `k8s` variable.
///
/// `verb` is the resource action (`get`/`list`/`create`/`update`/`patch`/`delete`),
/// derived from the HTTP method. `resource` and `namespace` come from the API path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sFacts {
    pub verb: String,
    pub resource: String,
    pub namespace: String,
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
