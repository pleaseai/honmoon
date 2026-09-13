//! Honmoon core: policy model, verdicts, and protocol facts.
//!
//! This crate is intentionally transport-agnostic. The proxy crate feeds it
//! protocol [`Facts`] and receives a [`Verdict`].
//!
//! Transport-agnostic is not I/O-free, and the difference is deliberate:
//! [`audit`] opens and appends to one file, the operator's JSONL audit sink, and
//! that is the only file this crate touches. Everything else takes what it works
//! on as an argument — [`Policy::from_yaml`] parses a string, and whoever read it
//! off disk is the caller. `crates/AGENTS.md` states the boundary and what stays
//! forbidden; [`audit::AuditLog::with_file`] says why the sink open is here.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

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
    AuditDraft, AuditEvent, AuditLog, AuditSinkFacts, Decision, FactsSummary, RedactionFacts,
    RedactionKeySource, RedactionTransport,
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
    /// Every `rules` condition compiled once, at load.
    ///
    /// Not part of the policy document — `#[serde(skip)]`, so it neither reads
    /// from nor writes to the YAML and JSON shapes TD-001 keeps in sync with
    /// the TypeScript model and the JSON Schema. It is derived state, built by
    /// [`Policy::from_yaml`] and carried so [`decide`] evaluates rather than
    /// compiles.
    ///
    /// Private, so no caller outside this crate can set or observe it: it is an
    /// optimization the engine owns, and a `Policy` that does not have one
    /// (built in code, or deserialized straight through `serde`) simply
    /// compiles at evaluation time as before. Nothing breaks if it is wrong or
    /// absent — see [`engine::CompiledConditions`] for why keying it by the
    /// condition text is what keeps a reassigned [`Rule::condition`] from being
    /// answered with a stale program.
    #[serde(skip)]
    compiled: engine::CompiledConditions,
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
    /// An unusable `endpoints` entry, a rule with a blank `condition`, and a
    /// rule whose `condition` the CEL compiler rejects are errors (see
    /// [`Policy::validate_endpoints`], [`Policy::validate_rules`] and
    /// [`Policy::validate_compiled_conditions`]); an *undefined* endpoint
    /// reference and an unreachable rule are only warnings (see
    /// [`Policy::warn_undefined_endpoints`] and
    /// [`Policy::warn_shadowed_rules`]).
    ///
    /// The compile check is last because it is the only one that needs the
    /// conditions compiled, and the compile is also what a policy that loads
    /// keeps. So a policy refused for a bad condition has already emitted the
    /// two warnings above — they are about other rules and still true, and an
    /// author fixing the file is better served seeing every complaint at once
    /// than one per run.
    pub fn from_yaml(src: &str) -> Result<Self, Error> {
        let mut policy: Self = serde_yaml::from_str(src).map_err(Error::Parse)?;
        policy.validate_endpoints()?;
        policy.validate_rules()?;
        policy.warn_undefined_endpoints();
        policy.warn_shadowed_rules();
        policy.compiled = engine::CompiledConditions::compile(&policy.rules);
        policy.validate_compiled_conditions()?;
        Ok(policy)
    }

    /// The load-time compiled conditions, empty for a `Policy` that was not
    /// built by [`Policy::from_yaml`].
    pub(crate) fn compiled_conditions(&self) -> &engine::CompiledConditions {
        &self.compiled
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
    /// either: switching a rule off is something a policy has no spelling for,
    /// so a blank condition reads as an authoring slip rather than an
    /// intention. It carries no expression, so it can never match and the rule
    /// sits in the policy looking active while doing nothing.
    ///
    /// So it fails the load, like an unusable `endpoints` entry, where the
    /// author sees it — rather than going unnoticed in production because an
    /// inert rule and a rule that simply did not match look identical.
    /// (It was originally rejected because `Program::compile` panicked on it
    /// rather than returning — #151. `cel` 0.14 returns `Err`, and the
    /// rejection stands on the reason above.)
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

    /// Reject rules whose `condition` the CEL compiler will not accept.
    ///
    /// A condition that does not compile can never match, so the rule sits in
    /// the policy looking active and answers nothing — the same failure mode a
    /// blank condition has, arrived at by a different route. Until #191 it was
    /// only a warning: the gateway started, the rule was inert, and an operator
    /// found out whenever somebody next read the log. It is an error now, where
    /// the author sees it, like an unusable `endpoints` entry.
    ///
    /// What closed the old objection is that there is no longer a crash to
    /// trade against. #154 declined load-time compilation because it "moves the
    /// panic from request time to startup"; on `cel` 0.14 every input class
    /// #151 and #154 measured returns `Err` rather than panicking (#164
    /// measured 12/17 panicking inputs before, 0/17 after), so what moves to
    /// startup is a diagnostic, not a panic.
    ///
    /// **Every** offending rule is reported, not the first. Three malformed
    /// conditions are three edits, and naming one per load would make that
    /// three runs to discover. That is what the loader's two per-rule warnings
    /// ([`Policy::warn_undefined_endpoints`] and `warn_shadowed_rules`) already
    /// do for the other two ways a rule goes inert; it differs from
    /// [`Policy::validate_rules`] and [`Policy::validate_endpoints`], which
    /// return on the first offender, because those read one field at a time
    /// while this one has already compiled every condition and so is holding
    /// the whole answer.
    ///
    /// A **blank** condition never reaches here: [`Policy::validate_rules`]
    /// returns before the compile, and its `"condition is blank"` message is
    /// the better one for the malformed condition an author writes by accident.
    fn validate_compiled_conditions(&self) -> Result<(), Error> {
        let rules: Vec<UncompilableRule> = self
            .compiled
            .inert_rules(&self.rules)
            .into_iter()
            .map(|(index, rule)| UncompilableRule {
                index,
                name: rule.name.clone(),
                condition: rule.condition.clone(),
            })
            .collect();

        if rules.is_empty() {
            return Ok(());
        }
        Err(Error::UncompilableRuleConditions { rules })
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
/// `\u{3000}` count), and nothing else. It is deliberately not a general test
/// for "carries no expression": since the move to `cel` 0.14 the compiler
/// returns `Err` for the wider malformed set that used to panic here — `"&&"`,
/// `"@"`, `"§"`, an emoji, a lone `\u{200b}` — so there is nothing left for a
/// pre-check to rescue, and widening this one to chase that set would mean
/// drawing a line the compiler does not draw. It stays because blank is the
/// case worth its own message, not because blank is the case that would crash.
/// The panic class it was written against is #154.
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

/// A rule whose `condition` is not a valid CEL expression, as named by
/// [`Error::UncompilableRuleConditions`].
///
/// Carries the rule's position as well as its name for the same reason
/// [`Error::BlankRuleCondition`] does: [`Rule::name`] is an ordinary field, not
/// a map key like an endpoint's, so nothing requires it to be unique or even
/// non-empty and on its own it can name two rules or none.
///
/// It carries the `condition` text too, which the blank error has no use for —
/// there the text is empty by definition, while here it is the thing the author
/// has to go and fix. A policy is parsed from a string, so the loader has no
/// line number to quote instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncompilableRule {
    /// Position in [`Policy::rules`].
    pub index: usize,
    /// The rule's [`name`](Rule::name), as written.
    pub name: String,
    /// The [`condition`](Rule::condition) text the compiler rejected.
    pub condition: String,
}

impl fmt::Display for UncompilableRule {
    /// Both author-written values are rendered with `{:?}` rather than wrapped
    /// in backticks, which is what the other variants here do with a `name`.
    ///
    /// The condition is why. Four of the classes this error exists to catch —
    /// a lone `U+200B`, BOM, word joiner or soft hyphen — are *invisible*, and
    /// between backticks they render as nothing: an operator would be told a
    /// condition is not valid CEL and shown an empty pair of backticks, which
    /// is precisely the "you would never spot it" problem the check is for.
    /// `{:?}` prints them as `"\u{200b}"`. It also escapes a newline or a
    /// control character, which otherwise breaks a report whose clauses are
    /// joined on one line, and it leaves ordinary CEL alone — `str`'s `Debug`
    /// escapes `"` and `\` but not `'`, so `sql.verb == 'DROP'` reads
    /// unchanged.
    ///
    /// The `name` follows for the same reason at one remove: it is the other
    /// value an author controls, it appears in the same joined line, and
    /// quoting the two halves of one clause differently would read as an
    /// accident.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {:?} (rules[{}]) has a `condition` that is not a valid CEL expression: {:?}",
            self.name, self.index, self.condition
        )
    }
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
    /// Every rule the CEL compiler rejected, in rule order — see
    /// [`Policy::validate_compiled_conditions`] for why all of them rather than
    /// the first.
    ///
    /// One clause per rule, joined with `; `, so a policy with a single bad
    /// condition reads exactly like the other single-cause errors here.
    #[error("{}", .rules.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    UncompilableRuleConditions { rules: Vec<UncompilableRule> },
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

    /// #151: a blank `condition` is not a rule that quietly matches nothing.
    /// It carries no expression, so it can never match and the rule is inert —
    /// an author error the loader should say out loud rather than accept.
    /// (It was originally rejected because `Program::compile` panicked on it;
    /// `cel` 0.14 returns `Err` instead, and the rejection stays on the reason
    /// above.)
    #[test]
    fn rejects_a_rule_with_a_blank_condition() {
        // `"\u00a0"` and `"\u3000"` are whitespace to `char::is_whitespace` but
        // not to an ASCII test — so a narrowing of `is_blank_condition` to
        // ASCII would let a condition an author cannot see load as a live rule.
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

    /// The two code points where Rust and the JSON Schema could have drifted.
    ///
    /// `is_blank_condition` follows `char::is_whitespace` (Unicode
    /// `White_Space`); the schema's mirror is an ECMAScript regex, whose `\s`
    /// differs from that set in exactly these two places — it omits `U+0085`
    /// and adds `U+FEFF`. The schema corrects for both
    /// (`packages/policy/src/policy.schema.test.ts` pins its side); this pins
    /// the side it is mirroring, so a change here cannot silently desync them.
    #[test]
    fn the_two_code_points_the_schema_mirror_turns_on() {
        // `U+0085` (NEXT LINE) is whitespace to Rust, so a condition of only
        // that is blank and does not load.
        let error = Policy::from_yaml(
            "rules:\n  - name: nel\n    endpoint: '*'\n    condition: \"\\u0085\"\n    verdict: allow\n",
        )
        .expect_err("U+0085 is whitespace, so the condition is blank");
        assert!(
            matches!(&error, Error::BlankRuleCondition { name, .. } if name == "nel"),
            "unexpected error: {error}"
        );

        // `U+FEFF` is *not* whitespace to Rust, so a condition of only that is
        // not blank and passes this check. It is still unevaluable — the CEL
        // compiler rejects it like any other lone character the lexer cannot
        // start a token with (#154) — so since #191 it fails the load at the
        // *compile* check instead, one step later.
        //
        // Which error comes back is what pins the boundary between the two
        // checks, and it is the whole point of this test: `is_blank_condition`
        // is an emptiness test, not a validity test, so a character that is
        // invisible without being whitespace has to fall to the compiler. A
        // narrowing or widening of `is_blank_condition` that moved this code
        // point would swap the variant here.
        let error = Policy::from_yaml(
            "rules:\n  - name: bom\n    endpoint: '*'\n    condition: \"\\ufeff\"\n    verdict: allow\n",
        )
        .expect_err("U+FEFF is not valid CEL either, so the policy does not load");
        let Error::UncompilableRuleConditions { rules } = &error else {
            panic!("U+FEFF is not whitespace, so this must not be the blank error: {error}");
        };
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "bom");
        assert_eq!(rules[0].condition, "\u{feff}");
    }

    /// [`is_blank_condition`] is about a condition with nothing in it, and
    /// nothing more: it does not inspect CEL syntax, which is why the compile
    /// check exists beside it. These conditions clear both — content, and an
    /// expression that compiles — including the one that is only `true` with
    /// spaces around it, since the blank test trims and the compiler does not
    /// mind.
    #[test]
    fn accepts_a_rule_whose_condition_has_content() {
        for condition in ["\"true\"", "\"sql.verb == 'DROP'\"", "\" true \""] {
            Policy::from_yaml(&format!(
                "rules:\n  - name: r\n    endpoint: '*'\n    condition: {condition}\n    verdict: allow\n"
            ))
            .unwrap_or_else(|error| panic!("condition {condition} should load: {error}"));
        }
    }

    /// #191: a condition the CEL compiler rejects fails the load, naming the
    /// rule and quoting the condition.
    ///
    /// The classes are #154's, minus the blank ones — those never reach the
    /// compile check, because `validate_rules` returns first and says
    /// "condition is blank" instead. Everything here is a condition an author
    /// wrote something into that CEL cannot read, including four that render
    /// as nothing in an editor and so are exactly the rules an operator would
    /// never spot going inert.
    #[test]
    fn rejects_a_rule_whose_condition_does_not_compile() {
        // Escaped for YAML, so the policy text carries the code point rather
        // than the escape.
        for (condition, written) in [
            ("\"&&\"", "&&"),
            ("\")\"", ")"),
            ("\"true &&\"", "true &&"),
            ("\"()\"", "()"),
            ("\"// nothing\"", "// nothing"),
            ("\"@\"", "@"),
            ("\"\\u00a7\"", "\u{00a7}"),
            // Astral plane, so YAML needs `\U` and eight digits — `\u` takes
            // exactly four and would carry a different string through.
            ("\"\\U0001f600\"", "\u{1f600}"),
            // Invisible without being whitespace: zero-width space, BOM, word
            // joiner, soft hyphen.
            ("\"\\u200b\"", "\u{200b}"),
            ("\"\\ufeff\"", "\u{feff}"),
            ("\"\\u2060\"", "\u{2060}"),
            ("\"\\u00ad\"", "\u{00ad}"),
        ] {
            let error = Policy::from_yaml(&format!(
                "rules:\n  - name: broken\n    endpoint: '*'\n    condition: {condition}\n    verdict: allow\n"
            ))
            .unwrap_err();

            let Error::UncompilableRuleConditions { rules } = &error else {
                panic!("condition {condition}: unexpected error: {error}");
            };
            assert_eq!(
                rules,
                &[UncompilableRule {
                    index: 0,
                    name: "broken".into(),
                    condition: written.to_string(),
                }],
                "condition {condition}"
            );
        }
    }

    /// Every offending rule is named, not the first — a policy with three
    /// malformed conditions is three edits, and reporting one per load would
    /// make that three runs to find them all.
    ///
    /// Also the reason the report carries positions: two of these rules are
    /// called `dup`, so the names alone do not say which rules they are.
    #[test]
    fn names_every_rule_whose_condition_does_not_compile() {
        let error = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  \
             - name: dup\n    endpoint: '*'\n    condition: \"&&\"\n    verdict: allow\n  \
             - name: sound\n    endpoint: '*'\n    condition: \"http.method == 'GET'\"\n    verdict: allow\n  \
             - name: dup\n    endpoint: '*'\n    condition: \"&&\"\n    verdict: allow\n  \
             - name: other\n    endpoint: '*'\n    condition: \"@\"\n    verdict: deny\n",
        )
        .expect_err("three conditions do not compile");

        let Error::UncompilableRuleConditions { rules } = &error else {
            panic!("unexpected error: {error}");
        };

        // In rule order, the sound rule skipped — and both rules sharing the
        // one unusable condition are there. The compiler is asked once for
        // `"&&"`; the accounting is per rule, so deduping it along with the
        // compile would leave the third rule unnamed and its author fixing the
        // policy twice.
        assert_eq!(
            rules,
            &[
                UncompilableRule {
                    index: 0,
                    name: "dup".into(),
                    condition: "&&".into(),
                },
                UncompilableRule {
                    index: 2,
                    name: "dup".into(),
                    condition: "&&".into(),
                },
                UncompilableRule {
                    index: 3,
                    name: "other".into(),
                    condition: "@".into(),
                },
            ]
        );

        // The message names each of them, so an operator reading stderr gets
        // what the struct carries. This is the whole diagnostic: a policy is
        // parsed from a string, so there is no line number to quote.
        let message = error.to_string();
        assert_eq!(
            message,
            "rule \"dup\" (rules[0]) has a `condition` that is not a valid CEL expression: \"&&\"; \
             rule \"dup\" (rules[2]) has a `condition` that is not a valid CEL expression: \"&&\"; \
             rule \"other\" (rules[3]) has a `condition` that is not a valid CEL expression: \"@\""
        );
    }

    /// A blank condition is still the blank error, not the compile one.
    ///
    /// `validate_rules` runs before the compile, so the message that tells an
    /// author what to write instead survives #191 — which matters because
    /// blank is the malformed condition they reach by accident, and
    /// `"is not a valid CEL expression: ``"` would tell them nothing.
    #[test]
    fn a_blank_condition_is_still_reported_as_blank() {
        let error = Policy::from_yaml(
            "rules:\n  - name: broken\n    endpoint: '*'\n    condition: \"&&\"\n    verdict: allow\n  \
             - name: blank\n    endpoint: '*'\n    condition: \"\"\n    verdict: allow\n",
        )
        .expect_err("neither condition is evaluable");

        assert!(
            matches!(&error, Error::BlankRuleCondition { index, name } if *index == 1 && name == "blank"),
            "the blank rule is reported as blank even though an earlier rule fails to compile: {error}"
        );
    }

    /// The other side of #191: a policy whose conditions all compile loads
    /// exactly as it did before, table and all.
    ///
    /// The guard on the change being a *rejection* of bad policies rather than
    /// a narrowing of what counts as a good one — `agent.yaml`, the shipped
    /// example, is covered separately by
    /// `engine::tests::shipped_example_policy_fires`.
    #[test]
    fn a_policy_whose_conditions_all_compile_still_loads() {
        let policy = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  \
             - name: drop\n    endpoint: postgres-prod\n    condition: \"sql.verb == 'DROP'\"\n    verdict: pause\n  \
             - name: secrets\n    endpoint: k8s-prod\n    condition: \"k8s.resource == 'secrets' && k8s.verb == 'delete'\"\n    verdict: deny\n  \
             - name: always\n    endpoint: '*'\n    condition: \"true\"\n    verdict: allow\n",
        )
        .expect("every condition compiles");

        assert_eq!(policy.rules.len(), 3);
        assert_eq!(policy.compiled_conditions().len(), 3);
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
