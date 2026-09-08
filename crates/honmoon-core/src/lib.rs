//! Honmoon core: policy model, verdicts, and protocol facts.
//!
//! This crate is intentionally transport-agnostic. The proxy crate feeds it
//! protocol [`Facts`] and receives a [`Verdict`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod claude_code_hook;
pub mod engine;
pub mod pii;
pub mod protocols;
pub mod redact;
pub mod secret_detect;
pub mod secret_tokenizer;

pub use audit::{AuditDraft, AuditEvent, AuditLog, Decision, FactsSummary};
pub use claude_code_hook::{
    ClaudeCodeHookVerdict, PathResolution, claude_code_hook_verdict, is_sensitive_path,
};
pub use engine::{Outcome, decide, decide_explained};
pub use pii::{PiiFacts, PiiSpan, detect_pii, detect_spans, summarize_spans};
pub use redact::{DEFAULT_MIN_PII_SEVERITY, RedactionOutcome, redact, redact_with_spans};
pub use secret_detect::{SecretFinding, detect_secrets};
pub use secret_tokenizer::{
    MAX_PLACEHOLDER_LEN, Mapping, MappingStore, PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX,
    SecretTokenizer, SecretTokenizerError, StreamingDetokenizer, detokenize,
};

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
    /// Named network targets a [`Rule::endpoint`] can refer to, keyed by name.
    ///
    /// Optional: policies that only use `endpoint: '*'` never need it.
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// A named network target: the `(host, port)` a client dials, plus the wire
/// protocol Honmoon should parse facts from once it gets there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: EndpointProtocol,
}

/// The wire protocol spoken at an [`Endpoint`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointProtocol {
    /// PostgreSQL wire protocol — reserved for the SOCKS5 data path.
    Postgres,
    /// Kubernetes API over HTTPS: intercepted requests get [`K8sFacts`].
    Kubernetes,
    /// No protocol parsing; the endpoint is a name only.
    #[default]
    Tcp,
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
    ///
    /// Undefined endpoint references are warned about, not rejected — see
    /// [`Policy::warn_undefined_endpoints`].
    pub fn from_yaml(src: &str) -> Result<Self, Error> {
        let policy: Self = serde_yaml::from_str(src).map_err(Error::Parse)?;
        policy.warn_undefined_endpoints();
        Ok(policy)
    }

    /// Look up the endpoint declared for the `(host, port)` a client dialed.
    ///
    /// The host is compared case-insensitively after trimming a trailing dot
    /// (FQDN root); the port must match exactly. No IP or wildcard resolution —
    /// a rule for an endpoint declared by a name that never resolves simply
    /// never matches, which is the fail-closed outcome.
    pub fn endpoint_for(&self, host: &str, port: u16) -> Option<(&str, &Endpoint)> {
        let host = host.trim_end_matches('.');
        self.endpoints.iter().find_map(|(name, endpoint)| {
            (endpoint.port == port
                && endpoint
                    .host
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(host))
            .then_some((name.as_str(), endpoint))
        })
    }

    /// Warn about rules referencing an endpoint that `endpoints` does not
    /// declare.
    ///
    /// Not an error: `Facts::endpoint` may be set by paths other than the
    /// `endpoints` map, so such a rule is merely inert here, and refusing to
    /// load the whole policy over it would fail *open* for every other rule.
    fn warn_undefined_endpoints(&self) {
        for rule in &self.rules {
            if rule.endpoint != "*" && !self.endpoints.contains_key(&rule.endpoint) {
                tracing::warn!(
                    rule = %rule.name,
                    endpoint = %rule.endpoint,
                    "policy rule references an endpoint not declared in `endpoints`"
                );
            }
        }
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

    fn endpoints_policy() -> Policy {
        Policy::from_yaml(
            r#"
endpoints:
  postgres-prod: { host: db.internal, port: 5432, protocol: postgres }
  k8s-prod: { host: K8s.Internal., port: 6443, protocol: kubernetes }
  cache: { host: redis.internal, port: 6379 }
"#,
        )
        .expect("valid policy")
    }

    #[test]
    fn parses_endpoints_map() {
        let policy = endpoints_policy();

        assert_eq!(policy.endpoints.len(), 3);
        let postgres = &policy.endpoints["postgres-prod"];
        assert_eq!(postgres.host, "db.internal");
        assert_eq!(postgres.port, 5432);
        assert_eq!(postgres.protocol, EndpointProtocol::Postgres);
    }

    #[test]
    fn endpoints_default_to_empty_and_protocol_to_tcp() {
        let policy = Policy::from_yaml("egress:\n  default: allow\n").expect("valid policy");
        assert!(policy.endpoints.is_empty());

        assert_eq!(
            endpoints_policy().endpoints["cache"].protocol,
            EndpointProtocol::Tcp
        );
    }

    #[test]
    fn endpoint_for_matches_host_case_insensitively() {
        let policy = endpoints_policy();

        let (name, endpoint) = policy
            .endpoint_for("k8s.internal", 6443)
            .expect("endpoint resolved");
        assert_eq!(name, "k8s-prod");
        assert_eq!(endpoint.protocol, EndpointProtocol::Kubernetes);
        assert_eq!(
            policy.endpoint_for("K8S.INTERNAL.", 6443).map(|e| e.0),
            Some("k8s-prod")
        );
    }

    #[test]
    fn endpoint_for_requires_an_exact_port_match() {
        let policy = endpoints_policy();

        assert!(policy.endpoint_for("k8s.internal", 443).is_none());
        assert!(policy.endpoint_for("other.internal", 6443).is_none());
    }
}
