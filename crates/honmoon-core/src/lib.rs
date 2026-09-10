//! Honmoon core: policy model, verdicts, and protocol facts.
//!
//! This crate is intentionally transport-agnostic. The proxy crate feeds it
//! protocol [`Facts`] and receives a [`Verdict`].

use std::collections::{BTreeMap, HashMap};

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
pub use engine::{Outcome, decide, decide_explained, decide_pii_audit_only};
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
///
/// Unknown keys are rejected (the JSON Schema forbids them too): a misspelled
/// `protocol` would otherwise fall back to [`EndpointProtocol::Tcp`] and
/// silently turn the endpoint's protocol inspection off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// An unusable `endpoints` entry is an error (see
    /// [`Policy::validate_endpoints`]); an *undefined* endpoint reference is only
    /// a warning (see [`Policy::warn_undefined_endpoints`]).
    pub fn from_yaml(src: &str) -> Result<Self, Error> {
        let policy: Self = serde_yaml::from_str(src).map_err(Error::Parse)?;
        policy.validate_endpoints()?;
        policy.warn_undefined_endpoints();
        Ok(policy)
    }

    /// Reject `endpoints` entries that could never resolve or that resolve
    /// ambiguously.
    ///
    /// Port 0 is not a dialable port (the JSON Schema requires 1–65535), and two
    /// names on the same target would make [`Policy::endpoint_for`] silently
    /// pick one and shadow the other — an author who wrote two rules would see
    /// only one of them fire. Both are the author's mistake, not untrusted
    /// input, so they fail the load loudly instead of degrading at request time.
    fn validate_endpoints(&self) -> Result<(), Error> {
        let mut seen: HashMap<(String, u16), &str> = HashMap::new();
        for (name, endpoint) in &self.endpoints {
            if endpoint.port == 0 {
                return Err(Error::EndpointPortZero { name: name.clone() });
            }
            let target = (normalize_host(&endpoint.host), endpoint.port);
            if let Some(first) = seen.insert(target, name.as_str()) {
                return Err(Error::DuplicateEndpointTarget {
                    first: first.to_owned(),
                    second: name.clone(),
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                });
            }
        }
        Ok(())
    }

    /// Look up the endpoint declared for the `(host, port)` a client dialed.
    ///
    /// The host is compared case-insensitively after trimming a trailing dot
    /// (FQDN root); the port must match exactly. No IP or wildcard resolution —
    /// a rule for an endpoint declared by a name that never resolves simply
    /// never matches, which is the fail-closed outcome.
    pub fn endpoint_for(&self, host: &str, port: u16) -> Option<(&str, &Endpoint)> {
        // Same normalization as `normalize_host`, without its allocation.
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

/// Canonicalize an endpoint host for comparison: drop a trailing FQDN dot and
/// lowercase.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse policy: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("endpoint `{name}` has port 0; valid ports are 1-65535")]
    EndpointPortZero { name: String },
    #[error(
        "endpoints `{first}` and `{second}` both target {host}:{port}; each target must have one name"
    )]
    DuplicateEndpointTarget {
        first: String,
        second: String,
        host: String,
        port: u16,
    },
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
    fn rejects_an_endpoint_with_port_zero() {
        let error = Policy::from_yaml("endpoints:\n  broken: { host: db.internal, port: 0 }\n")
            .expect_err("port 0 is not dialable");

        assert!(
            matches!(&error, Error::EndpointPortZero { name } if name == "broken"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_two_endpoints_on_the_same_target() {
        let error = Policy::from_yaml(
            r#"
endpoints:
  k8s-prod: { host: k8s.internal, port: 6443 }
  k8s-alias: { host: K8s.Internal., port: 6443 }
"#,
        )
        .expect_err("a target must have a single name");

        let Error::DuplicateEndpointTarget { first, second, .. } = &error else {
            panic!("unexpected error: {error}");
        };
        // `endpoints` is a BTreeMap, so the reported order is by name.
        assert_eq!((first.as_str(), second.as_str()), ("k8s-alias", "k8s-prod"));
    }

    /// A misspelled key must not silently disable protocol inspection: without
    /// `deny_unknown_fields`, `protcol: postgres` would parse as a `tcp`
    /// endpoint and every SQL rule for it would go inert.
    #[test]
    fn rejects_an_endpoint_with_an_unknown_key() {
        let error = Policy::from_yaml(
            "endpoints:\n  db: { host: db.internal, port: 5432, protcol: postgres }\n",
        )
        .expect_err("a misspelled key must not parse");

        assert!(
            matches!(error, Error::Parse(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn endpoint_for_requires_an_exact_port_match() {
        let policy = endpoints_policy();

        assert!(policy.endpoint_for("k8s.internal", 443).is_none());
        assert!(policy.endpoint_for("other.internal", 6443).is_none());
    }
}
