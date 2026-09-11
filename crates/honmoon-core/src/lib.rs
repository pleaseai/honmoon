//! Honmoon core: policy model, verdicts, and protocol facts.
//!
//! This crate is intentionally transport-agnostic. The proxy crate feeds it
//! protocol [`Facts`] and receives a [`Verdict`].

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod claude_code_hook;
pub mod engine;
pub mod hook_salt;
pub mod pii;
pub mod protocols;
pub mod redact;
pub mod secret_detect;
pub mod secret_tokenizer;

pub use audit::{
    AuditDraft, AuditEvent, AuditLog, Decision, FactsSummary, RedactionFacts, RedactionKeySource,
    RedactionTransport,
};
pub use claude_code_hook::{
    ClaudeCodeHookVerdict, PathResolution, claude_code_hook_verdict, is_sensitive_path,
};
pub use engine::{Outcome, decide, decide_explained, decide_pii_audit_only};
pub use hook_salt::{derive_hook_salt, hook_salt_context};
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
    /// An unusable `endpoints` entry and a rule with a blank `condition` are
    /// errors (see [`Policy::validate_endpoints`] and
    /// [`Policy::validate_rules`]); an *undefined* endpoint reference and an
    /// unreachable rule are only warnings (see
    /// [`Policy::warn_undefined_endpoints`] and
    /// [`Policy::warn_shadowed_rules`]).
    pub fn from_yaml(src: &str) -> Result<Self, Error> {
        let policy: Self = serde_yaml::from_str(src).map_err(Error::Parse)?;
        policy.validate_endpoints()?;
        policy.validate_rules()?;
        policy.warn_undefined_endpoints();
        policy.warn_shadowed_rules();
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

    /// Reject rules whose `condition` is blank.
    ///
    /// A blank condition says nothing, and the two things an author might mean
    /// by it are both unavailable. It is not "always" — that is the literal
    /// `true` (see [`is_unconditional`]). And it is not a rule switched off
    /// either: a condition that cannot compile normally declines and lets the
    /// walk continue, but `Program::compile` does not *return* on a blank
    /// input, it panics (#151), so the rule would take the decision path down
    /// at the first request that reached it.
    ///
    /// So the policy is unevaluable, and like an unusable `endpoints` entry it
    /// fails the load, where the author sees it — rather than at request time,
    /// in production, on whichever request first reaches the rule.
    ///
    /// The error carries the rule's position as well as its name. `name` is an
    /// ordinary field here, not a map key like an endpoint's: nothing requires
    /// it to be unique or even non-empty, so on its own it can name two rules
    /// or none.
    fn validate_rules(&self) -> Result<(), Error> {
        for (index, rule) in self.rules.iter().enumerate() {
            if is_blank_condition(&rule.condition) {
                return Err(Error::BlankRuleCondition {
                    index,
                    name: rule.name.clone(),
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

    /// Warn about rules an earlier unconditional rule makes unreachable.
    ///
    /// The first matching rule wins, so a rule whose condition is always true
    /// answers every request its endpoint covers and nothing below it on that
    /// endpoint is ever reached. That is the shape ADR-0007 asks an
    /// `egress.default: deny` policy to write for a `postgres` endpoint — a
    /// connection-level `condition: "true"` allow — and putting it above the
    /// statement rules silently answers every query with `allow`.
    ///
    /// A warning, not an error: the ordering is legal, the policy still means
    /// exactly what it says, and this changes no verdict. It only names the
    /// pair so the author can see which rule is dead and what killed it.
    fn warn_shadowed_rules(&self) {
        for (rule, shadowed_by) in self.shadowed_rules() {
            tracing::warn!(
                rule = %rule.name,
                shadowed_by = %shadowed_by.name,
                endpoint = %rule.endpoint,
                "policy rule is unreachable: an earlier unconditional rule always matches first"
            );
        }
    }

    /// Every `(unreachable rule, the earlier rule that shadows it)` pair, in
    /// rule order.
    ///
    /// Quadratic in the rule count, which is a load-time cost over a
    /// hand-written list; a rule is reported once, against the *first* rule
    /// that shadows it.
    fn shadowed_rules(&self) -> Vec<(&Rule, &Rule)> {
        self.rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| {
                let shadowed_by = self.rules[..index].iter().find(|earlier| {
                    is_unconditional(&earlier.condition)
                        && endpoint_covers(&earlier.endpoint, &rule.endpoint)
                })?;
                Some((rule, shadowed_by))
            })
            .collect()
    }
}

/// Whether a condition matches every request the rule's endpoint is consulted
/// for, so the rule is an unconditional answer rather than a test.
///
/// Deliberately syntactic: only the literal `true` that ADR-0007 tells authors
/// to write for a connection-level allow counts. An expression that merely
/// *happens* to be always true (`1 == 1`) is left alone — proving a CEL
/// expression total is not something the loader can do, and a warning that
/// guessed would teach authors to ignore it.
///
/// A **blank** condition is not unconditional either, despite reading like
/// one: it is not valid CEL, so the rule could never match. A loaded policy
/// never reaches this check carrying one — [`Policy::validate_rules`] refuses
/// it — but the test stays purely syntactic, so a `Policy` built in code
/// shadows nothing on a blank condition either.
fn is_unconditional(condition: &str) -> bool {
    condition.trim() == "true"
}

/// Whether a condition carries no expression at all.
///
/// The one malformed condition the loader recognises, and the one place the
/// engine departs from "hand it to the compiler and see". Shared so the
/// load-time rejection and the engine's own guard cannot drift apart: they
/// must agree on exactly which conditions never reach `Program::compile`.
///
/// Whitespace as Rust defines it (`char::is_whitespace`, so `\u{00a0}` and
/// `\u{3000}` count), and nothing else. It is not a general test for "carries
/// no expression", because no cheap one exists: `Program::compile` panics on
/// *any* single character it cannot begin a token with, so `"&&"`, `"@"`,
/// `"§"`, an emoji and a lone `\u{200b}` all panic exactly as `""` did. The
/// last of those matters most here — a zero-width space is not
/// `char::is_whitespace`, so a condition made only of them reads as empty in
/// an editor, is *not* blank by this test, and still panics. Recognising it
/// would mean drawing a line the compiler does not draw. That whole class is
/// #154; this function is only the part of it that is cheap to name.
pub(crate) fn is_blank_condition(condition: &str) -> bool {
    condition.trim().is_empty()
}

/// Whether a rule bound to `pattern` is consulted on every request a rule bound
/// to `other` would be — the ordering half of shadowing.
///
/// Mirrors the engine's own endpoint match (`*` matches any endpoint, otherwise
/// the name must be equal): `*` covers every endpoint, and a name covers only
/// itself. So an endpoint-specific rule never shadows a later `*` rule, which
/// stays reachable through every *other* endpoint.
fn endpoint_covers(pattern: &str, other: &str) -> bool {
    pattern == "*" || pattern == other
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
        "rule `{name}` (rules[{index}]) has a blank `condition`; write `\"true\"` for a rule that always matches"
    )]
    BlankRuleCondition { index: usize, name: String },
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

    /// A blank condition reads like "no condition", but it is not valid CEL, so
    /// such a rule matches nothing and shadows nothing.
    ///
    /// Built in code rather than parsed: `from_yaml` rejects a blank condition
    /// outright now (see `rejects_a_rule_with_a_blank_condition`), so this is
    /// the only shape that still carries one into the shadowing check — and the
    /// assertion is the same one the `""` case of
    /// `only_a_literal_true_condition_counts_as_unconditional` used to make.
    #[test]
    fn a_blank_condition_does_not_count_as_unconditional() {
        for condition in ["", " ", "\n"] {
            let policy = Policy {
                rules: vec![
                    Rule {
                        name: "first".into(),
                        endpoint: "postgres-prod".into(),
                        condition: condition.to_string(),
                        verdict: Verdict::Allow,
                    },
                    Rule {
                        name: "sql-no-prod-drop".into(),
                        endpoint: "postgres-prod".into(),
                        condition: "sql.verb == 'DROP'".into(),
                        verdict: Verdict::Deny,
                    },
                ],
                ..Default::default()
            };

            assert!(
                shadowed_names(&policy).is_empty(),
                "condition {condition:?} must not count as unconditional"
            );
        }
    }

    /// #151: a blank `condition` is not a rule that quietly matches nothing —
    /// `Program::compile` panics on it rather than returning the `Err` the
    /// engine degrades on, so the policy is unevaluable and must not load.
    #[test]
    fn rejects_a_rule_with_a_blank_condition() {
        // `"\u00a0"` and `"\u3000"` are whitespace to `char::is_whitespace` but
        // not to an ASCII test, and they panic in `Program::compile` exactly as
        // `""` does — so a narrowing of `is_blank_condition` to ASCII would put
        // the #151 panic back for a condition an author cannot see.
        for condition in [
            "\"\"",
            "\" \"",
            "\"\\n\"",
            "\"\\t\\r\\n\"",
            "\"\\u00a0\"",
            "\"\\u3000\"",
        ] {
            let error = Policy::from_yaml(&format!(
                "rules:\n  - name: blank\n    endpoint: '*'\n    condition: {condition}\n    verdict: allow\n"
            ))
            .expect_err("a blank condition is not evaluable");

            assert!(
                matches!(&error, Error::BlankRuleCondition { index, name } if *index == 0 && name == "blank"),
                "condition {condition}: unexpected error: {error}"
            );
        }

        // The reported position is the rule's own, not the first rule's.
        let error = Policy::from_yaml(
            "rules:\n  - name: ok\n    endpoint: '*'\n    condition: \"true\"\n    verdict: allow\n  - name: blank\n    endpoint: '*'\n    condition: \"\"\n    verdict: allow\n",
        )
        .expect_err("a blank condition is not evaluable");
        assert!(
            matches!(&error, Error::BlankRuleCondition { index, name } if *index == 1 && name == "blank"),
            "unexpected error: {error}"
        );
    }

    /// The load-time check is about a condition with nothing in it, not about
    /// a condition the loader dislikes: it never inspects CEL syntax.
    #[test]
    fn accepts_a_rule_whose_condition_has_content() {
        for condition in ["\"true\"", "\"sql.verb == 'DROP'\"", "\" true \""] {
            Policy::from_yaml(&format!(
                "rules:\n  - name: r\n    endpoint: '*'\n    condition: {condition}\n    verdict: allow\n"
            ))
            .unwrap_or_else(|error| panic!("condition {condition} should load: {error}"));
        }
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

    /// `(unreachable rule, the rule that shadows it)` by name — what
    /// `warn_shadowed_rules` puts in the log.
    fn shadowed_names(policy: &Policy) -> Vec<(&str, &str)> {
        policy
            .shadowed_rules()
            .into_iter()
            .map(|(rule, shadowed_by)| (rule.name.as_str(), shadowed_by.name.as_str()))
            .collect()
    }

    /// The defect from the ADR-0007 consequence: the connection-level allow an
    /// `egress.default: deny` policy needs, written *above* the statement
    /// rules, answers every query.
    #[test]
    fn an_unconditional_rule_shadows_later_rules_on_the_same_endpoint() {
        let policy = Policy::from_yaml(
            r#"
endpoints:
  postgres-prod: { host: db.internal, port: 5432, protocol: postgres }
rules:
  - name: postgres-connect
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: deny
"#,
        )
        .expect("valid policy");

        assert_eq!(
            shadowed_names(&policy),
            vec![("sql-no-prod-drop", "postgres-connect")]
        );

        // Diagnostic only: the warning names the dead rule, it does not revive
        // it. A `DROP` still gets the shadowing rule's `allow`.
        let facts = Facts {
            endpoint: Some("postgres-prod".to_string()),
            sql: Some(SqlFacts {
                verb: "DROP".to_string(),
                table: "users".to_string(),
            }),
            ..Default::default()
        };
        assert_eq!(crate::decide(&policy, &facts), Verdict::Allow);
    }

    /// The normal connection-allow shape: one unconditional rule with nothing
    /// below it is exactly what ADR-0007 asks for, and must stay silent.
    #[test]
    fn a_lone_unconditional_rule_shadows_nothing() {
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: postgres-connect
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
"#,
        )
        .expect("valid policy");

        assert!(shadowed_names(&policy).is_empty());
    }

    /// Shadowing is order-sensitive: the same rules ordered the way ADR-0007
    /// prescribes — statement denies first, the connection allow last — are all
    /// reachable.
    #[test]
    fn an_unconditional_rule_ordered_last_shadows_nothing() {
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: deny
  - name: postgres-connect
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
"#,
        )
        .expect("valid policy");

        assert!(shadowed_names(&policy).is_empty());
    }

    /// `*` matches any endpoint, so an unconditional `*` rule is reached before
    /// every later rule whatever endpoint that rule names.
    #[test]
    fn an_unconditional_wildcard_rule_shadows_every_later_rule() {
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: allow-everything
    endpoint: '*'
    condition: "true"
    verdict: allow
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: deny
  - name: k8s-no-secret-delete
    endpoint: k8s-prod
    condition: "k8s.resource == 'secrets'"
    verdict: deny
"#,
        )
        .expect("valid policy");

        assert_eq!(
            shadowed_names(&policy),
            vec![
                ("sql-no-prod-drop", "allow-everything"),
                ("k8s-no-secret-delete", "allow-everything"),
            ]
        );
    }

    /// Shadowing is per endpoint. An unconditional rule bound to one endpoint
    /// leaves another endpoint's rules alone, and leaves a later `*` rule
    /// reachable — through every endpoint it does not cover.
    #[test]
    fn an_unconditional_rule_does_not_shadow_other_endpoints() {
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: postgres-connect
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
  - name: k8s-no-secret-delete
    endpoint: k8s-prod
    condition: "k8s.resource == 'secrets'"
    verdict: deny
  - name: http-block-large-upload
    endpoint: '*'
    condition: "http.body_size > 10485760"
    verdict: deny
"#,
        )
        .expect("valid policy");

        assert!(shadowed_names(&policy).is_empty());
    }

    /// A rule is reported once, against the *first* rule that shadows it — and
    /// an unconditional rule is not exempt from being shadowed itself, which is
    /// what a duplicated connection-allow looks like.
    #[test]
    fn a_shadowed_rule_is_reported_against_the_first_rule_that_shadows_it() {
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: postgres-connect
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
  - name: postgres-connect-again
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: deny
"#,
        )
        .expect("valid policy");

        // Both later rules name `postgres-connect`, not the nearer duplicate:
        // it is the rule that actually answers the request.
        assert_eq!(
            shadowed_names(&policy),
            vec![
                ("postgres-connect-again", "postgres-connect"),
                ("sql-no-prod-drop", "postgres-connect"),
            ]
        );
    }

    /// Only the literal `true` counts. `1 == 1` is always true but the loader
    /// cannot prove that, and a false positive here would teach authors to
    /// ignore the warning.
    #[test]
    fn only_a_literal_true_condition_counts_as_unconditional() {
        for condition in ["1 == 1", "false", "'true'"] {
            let policy = Policy::from_yaml(&format!(
                r#"
rules:
  - name: first
    endpoint: postgres-prod
    condition: "{condition}"
    verdict: allow
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: deny
"#
            ))
            .expect("valid policy");

            assert!(
                shadowed_names(&policy).is_empty(),
                "condition {condition:?} must not count as unconditional"
            );
        }

        // Surrounding whitespace is not a different condition, though.
        let policy = Policy::from_yaml(
            r#"
rules:
  - name: first
    endpoint: postgres-prod
    condition: "  true  "
    verdict: allow
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP'"
    verdict: deny
"#,
        )
        .expect("valid policy");
        assert_eq!(shadowed_names(&policy), vec![("sql-no-prod-drop", "first")]);
    }
}
