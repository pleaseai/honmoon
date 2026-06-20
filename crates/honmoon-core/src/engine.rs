//! Policy decision engine: protocol-aware CEL rules + egress domain lists.

use cel_interpreter::{Context, Program, Value};

use crate::{Facts, Policy, Verdict};

/// Decide the [`Verdict`] for `facts` under `policy`.
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
pub fn decide(policy: &Policy, facts: &Facts) -> Verdict {
    for rule in &policy.rules {
        if endpoint_matches(&rule.endpoint, facts.endpoint.as_deref())
            && eval_condition(&rule.condition, facts)
        {
            return rule.verdict;
        }
    }
    egress_verdict(policy, facts)
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
    // TODO(phase 3): add `sql` / `k8s` variables from facts.

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
}
