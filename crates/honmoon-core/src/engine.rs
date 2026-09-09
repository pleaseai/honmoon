//! Policy decision engine: protocol-aware CEL rules + egress domain lists.

use cel_interpreter::{Context, Program, Value};

use crate::{Facts, Policy, Verdict};

/// A decision plus the reason it was reached.
///
/// `rule` names the protocol rule that fired (if any); when `None`, the verdict
/// came from the egress allow/deny lists or the egress default. This is what the
/// audit log records so a human can see *why* a request was held or blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,
    /// Name of the matched [`Rule`](crate::Rule), or `None` for an egress decision.
    pub rule: Option<String>,
}

/// Decide the [`Verdict`] for `facts` under `policy`.
///
/// Thin wrapper over [`decide_explained`] for callers that only need the verdict.
pub fn decide(policy: &Policy, facts: &Facts) -> Verdict {
    decide_explained(policy, facts).verdict
}

/// Decide the [`Outcome`] (verdict + matched rule) for `facts` under `policy`.
///
/// Precedence:
/// 1. Protocol-aware [`Rule`](crate::Rule)s are evaluated **in order**. The first
///    rule whose `endpoint` matches and whose CEL `condition` evaluates to `true`
///    wins and returns its verdict.
/// 2. If no rule matches, the egress domain lists decide: a `deny` match → `Deny`,
///    else an `allow` match → `Allow`, else `egress.default`.
///
/// Fail-closed: a rule whose condition fails to compile or references unknown
/// facts simply does not match (it cannot turn a deny into an allow), and the
/// egress default is `deny`.
pub fn decide_explained(policy: &Policy, facts: &Facts) -> Outcome {
    decide_rules(policy, facts, false)
}

/// Decide the [`Outcome`] as if content scanning never ran: rules whose CEL
/// conditions read `pii` are skipped entirely rather than evaluated against the
/// empty default summary, so an "allow-clean" rule (`pii.count == 0`) cannot
/// mask a later endpoint or Kubernetes deny. This is what detect mode enforces:
/// the policy's decision on the facts it is willing to act on.
///
/// Egress precedence is unchanged — when no non-`pii` rule matches, the domain
/// lists and `egress.default` decide exactly as in [`decide_explained`].
pub fn decide_without_pii_rules(policy: &Policy, facts: &Facts) -> Outcome {
    decide_rules(policy, facts, true)
}

/// Shared rule loop for [`decide_explained`] and [`decide_without_pii_rules`].
///
/// With `skip_pii_rules`, a rule whose condition references the `pii` variable
/// is passed over as if it were not in the policy at all.
fn decide_rules(policy: &Policy, facts: &Facts, skip_pii_rules: bool) -> Outcome {
    for rule in &policy.rules {
        if skip_pii_rules && condition_reads_pii(&rule.condition) {
            continue;
        }
        if endpoint_matches(&rule.endpoint, facts.endpoint.as_deref())
            && eval_condition(&rule.condition, facts)
        {
            return Outcome {
                verdict: rule.verdict,
                rule: Some(rule.name.clone()),
            };
        }
    }
    Outcome {
        verdict: egress_verdict(policy, facts),
        rule: None,
    }
}

/// Whether a CEL condition reads the `pii` variable, via the parsed expression's
/// reference set (never a substring match on the condition text).
///
/// A condition that fails to compile is reported as *not* reading `pii`: it can
/// never match either way, so skipping it changes nothing and the fail-closed
/// behaviour of [`eval_condition`] is preserved.
fn condition_reads_pii(condition: &str) -> bool {
    Program::compile(condition).is_ok_and(|program| program.references().has_variable("pii"))
}

fn egress_verdict(policy: &Policy, facts: &Facts) -> Verdict {
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

/// `*` matches any endpoint; otherwise an exact match is required.
fn endpoint_matches(pattern: &str, endpoint: Option<&str>) -> bool {
    pattern == "*" || endpoint == Some(pattern)
}

/// Match a domain against a pattern supporting a leading `*.` wildcard.
///
/// Case-insensitive on both sides; callers should still pass a canonicalized
/// (lowercased, trailing-dot-stripped) `domain`.
pub fn matches_domain(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain == suffix || domain.ends_with(&format!(".{suffix}"))
    } else {
        pattern == domain
    }
}

/// Evaluate a CEL condition against the facts. Any error → `false` (no match).
fn eval_condition(condition: &str, facts: &Facts) -> bool {
    let Ok(program) = Program::compile(condition) else {
        tracing::warn!(%condition, "policy rule condition failed to compile");
        return false;
    };

    let mut ctx = Context::default();
    if let Some(http) = &facts.http {
        if let Ok(value) = cel_interpreter::to_value(http) {
            ctx.add_variable_from_value("http", value);
        }
    }
    if let Some(sql) = &facts.sql {
        if let Ok(value) = cel_interpreter::to_value(sql) {
            ctx.add_variable_from_value("sql", value);
        }
    }
    if let Some(k8s) = &facts.k8s {
        if let Ok(value) = cel_interpreter::to_value(k8s) {
            ctx.add_variable_from_value("k8s", value);
        }
    }
    // Always register `pii` (default = empty) so absence conditions like
    // `pii.count == 0` are expressible, not just `pii.count > 0`.
    let pii = facts.pii.clone().unwrap_or_default();
    if let Ok(value) = cel_interpreter::to_value(&pii) {
        ctx.add_variable_from_value("pii", value);
    }

    matches!(program.execute(&ctx), Ok(Value::Bool(true)))
}

#[cfg(test)]
mod tests {
    use crate::{Facts, HttpFacts, Policy, Verdict};

    fn domain_facts(domain: &str) -> Facts {
        Facts {
            domain: Some(domain.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn egress_allow_deny_and_default() {
        let policy = Policy::from_yaml(
            "egress:\n  default: deny\n  allow:\n    - github.com\n    - '*.gh.io'\n  deny:\n    - bad.gh.io\n",
        )
        .unwrap();

        assert_eq!(
            super::decide(&policy, &domain_facts("github.com")),
            Verdict::Allow
        );
        assert_eq!(
            super::decide(&policy, &domain_facts("x.gh.io")),
            Verdict::Allow
        );
        assert_eq!(
            super::decide(&policy, &domain_facts("bad.gh.io")),
            Verdict::Deny
        ); // deny wins
        assert_eq!(
            super::decide(&policy, &domain_facts("evil.com")),
            Verdict::Deny
        ); // default
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(super::matches_domain("GitHub.com", "github.com"));
        assert!(super::matches_domain("*.GH.io", "raw.gh.io"));
    }

    #[test]
    fn cel_rule_matches_http_fact() {
        let policy = Policy::from_yaml(
            "rules:\n  - name: block-post\n    endpoint: '*'\n    condition: \"http.method == 'POST'\"\n    verdict: deny\n",
        )
        .unwrap();

        let mut facts = Facts {
            http: Some(HttpFacts::default()),
            ..Default::default()
        };
        facts.http.as_mut().unwrap().method = "POST".into();
        assert_eq!(super::decide(&policy, &facts), Verdict::Deny);

        facts.http.as_mut().unwrap().method = "GET".into();
        // Rule does not match → falls through to egress default (deny).
        assert_eq!(super::decide(&policy, &facts), Verdict::Deny);
    }

    #[test]
    fn rule_endpoint_must_match() {
        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: only-prod\n    endpoint: postgres-prod\n    condition: \"http.method == 'POST'\"\n    verdict: deny\n",
        )
        .unwrap();

        // endpoint mismatch → rule skipped → egress default (allow)
        let mut facts = Facts {
            endpoint: Some("other".into()),
            http: Some(HttpFacts {
                method: "POST".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &facts), Verdict::Allow);

        facts.endpoint = Some("postgres-prod".into());
        assert_eq!(super::decide(&policy, &facts), Verdict::Deny);
    }

    #[test]
    fn unknown_fact_reference_does_not_match() {
        // `sql` is not provided yet → condition errors → no match → egress default.
        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: sql\n    endpoint: '*'\n    condition: \"sql.verb == 'DROP'\"\n    verdict: deny\n",
        )
        .unwrap();
        assert_eq!(super::decide(&policy, &Facts::default()), Verdict::Allow);
    }

    /// Phase 3 exit criteria: a DROP/TRUNCATE against `postgres-prod` is caught,
    /// and a `delete secrets` against `k8s-prod` is caught — end to end from a
    /// raw PostgreSQL packet / K8s request through the parsers into `decide()`.
    #[test]
    fn protocol_facts_drive_policy_end_to_end() {
        use crate::protocols::{parse_k8s_request, parse_postgres_query};

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: no-prod-drop\n    endpoint: postgres-prod\n    condition: \"sql.verb == 'DROP' || sql.verb == 'TRUNCATE'\"\n    verdict: pause\n  \
             - name: no-prod-secret-delete\n    endpoint: k8s-prod\n    condition: \"k8s.resource == 'secrets' && k8s.verb == 'delete'\"\n    verdict: deny\n",
        )
        .unwrap();

        // PostgreSQL: DROP TABLE on postgres-prod → pause.
        let body = b"DROP TABLE users;\0";
        let mut pkt = vec![b'Q'];
        pkt.extend_from_slice(&((4 + body.len()) as u32).to_be_bytes());
        pkt.extend_from_slice(body);
        let sql = parse_postgres_query(&pkt);
        let pg_facts = Facts {
            endpoint: Some("postgres-prod".into()),
            sql,
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &pg_facts), Verdict::Pause);

        // K8s: DELETE a secret on k8s-prod → deny.
        let k8s_facts = Facts {
            endpoint: Some("k8s-prod".into()),
            k8s: Some(parse_k8s_request(
                "DELETE",
                "/api/v1/namespaces/prod/secrets/db",
            )),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &k8s_facts), Verdict::Deny);

        // A harmless SELECT on postgres-prod → no rule matches → egress default (allow).
        let safe = Facts {
            endpoint: Some("postgres-prod".into()),
            sql: parse_postgres_query(&{
                let b = b"SELECT 1\0";
                let mut p = vec![b'Q'];
                p.extend_from_slice(&((4 + b.len()) as u32).to_be_bytes());
                p.extend_from_slice(b);
                p
            }),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &safe), Verdict::Allow);
    }

    /// Phase 5 exit criterion: a request body carrying a valid-checksum RRN is
    /// caught by a `pii.*` rule, while a clean body falls through to allow.
    #[test]
    fn pii_findings_drive_policy_end_to_end() {
        use crate::detect_pii;

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: block-high-severity-pii\n    endpoint: api-egress\n    condition: \"pii.count > 0 && pii.max_severity >= 3\"\n    verdict: deny\n",
        )
        .unwrap();

        // Body with a valid RRN → high severity → deny.
        let leak = Facts {
            endpoint: Some("api-egress".into()),
            pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &leak), Verdict::Deny);

        // Body with no PII → no facts → rule cannot match → egress default (allow).
        let clean = Facts {
            endpoint: Some("api-egress".into()),
            pii: detect_pii(r#"{"order":"ORD-1234567890"}"#),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &clean), Verdict::Allow);
    }

    /// `pii` is always bound (default empty), so absence conditions like
    /// `pii.count == 0` are expressible even when no detection ran.
    #[test]
    fn pii_absence_condition_is_expressible() {
        let policy = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  \
             - name: allow-clean\n    endpoint: api-egress\n    condition: \"pii.count == 0\"\n    verdict: allow\n",
        )
        .unwrap();

        let clean = Facts {
            endpoint: Some("api-egress".into()),
            pii: None, // no PII facts at all
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &clean), Verdict::Allow);
    }

    /// Regression for #99: an "allow-clean" rule (`pii.count == 0`) placed
    /// before an endpoint-bound Kubernetes deny must not mask that deny once
    /// the PII scanner's findings are taken off the table.
    ///
    /// [`decide_without_pii_rules`](super::decide_without_pii_rules) skips the
    /// `pii`-reading rule outright, so the endpoint deny still wins — which is
    /// what detect mode enforces.
    #[test]
    fn pii_rules_are_skipped_not_rebound_to_an_empty_summary() {
        use crate::detect_pii;
        use crate::protocols::parse_k8s_request;

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: allow-clean\n    endpoint: '*'\n    condition: \"pii.count == 0\"\n    verdict: allow\n  \
             - name: no-prod-secret-delete\n    endpoint: k8s-prod\n    condition: \"k8s.resource == 'secrets' && k8s.verb == 'delete'\"\n    verdict: deny\n",
        )
        .unwrap();

        // Real PII findings in the body → allow-clean does not match, so the
        // endpoint deny wins on the plain path too.
        let leak = Facts {
            endpoint: Some("k8s-prod".into()),
            k8s: Some(parse_k8s_request(
                "DELETE",
                "/api/v1/namespaces/prod/secrets/db",
            )),
            pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
            ..Default::default()
        };
        assert!(leak.pii.as_ref().is_some_and(|p| p.count > 0));
        assert_eq!(super::decide(&policy, &leak), Verdict::Deny);
        assert_eq!(
            super::decide_without_pii_rules(&policy, &leak),
            super::Outcome {
                verdict: Verdict::Deny,
                rule: Some("no-prod-secret-delete".into()),
            }
        );

        // The masking this function exists to avoid: clearing `pii` binds the
        // empty default, allow-clean matches first, and the deny disappears.
        let cleared = Facts {
            pii: None,
            ..leak.clone()
        };
        assert_eq!(super::decide(&policy, &cleared), Verdict::Allow);

        // Skipping is unconditional — it does not depend on the summary being
        // non-empty. Clean facts on the bound endpoint still lose allow-clean,
        // so the k8s deny is reached all the same.
        let clean_delete = Facts {
            pii: detect_pii(r#"{"order":"ORD-1234567890"}"#),
            ..leak.clone()
        };
        assert_eq!(super::decide(&policy, &clean_delete), Verdict::Allow);
        assert_eq!(
            super::decide_without_pii_rules(&policy, &clean_delete)
                .rule
                .as_deref(),
            Some("no-prod-secret-delete")
        );

        // With no rule left to match, egress precedence is untouched.
        let unbound = Facts {
            endpoint: Some("api-egress".into()),
            pii: None,
            ..Default::default()
        };
        assert_eq!(
            super::decide_without_pii_rules(&policy, &unbound),
            super::Outcome {
                verdict: Verdict::Allow, // egress default
                rule: None,
            }
        );
    }

    /// Guards the shipped example policy against parser/condition drift: the
    /// real `policies/agent.yaml` rules must fire for the facts our parsers emit.
    #[test]
    fn shipped_example_policy_fires() {
        use crate::protocols::parse_k8s_request;

        let policy = Policy::from_yaml(include_str!("../../../policies/agent.yaml")).unwrap();

        let k8s = Facts {
            endpoint: Some("k8s-prod".into()),
            k8s: Some(parse_k8s_request(
                "DELETE",
                "/api/v1/namespaces/prod/secrets/db",
            )),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &k8s), Verdict::Deny);

        let sql = Facts {
            endpoint: Some("postgres-prod".into()),
            sql: Some(crate::protocols::parse_sql("TRUNCATE accounts")),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &sql), Verdict::Pause);
    }
}
