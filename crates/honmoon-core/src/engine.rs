//! Policy decision engine: protocol-aware CEL rules + egress domain lists.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};

use cel::{Context, Env, Program, Value};

use crate::{Facts, PiiFacts, Policy, Rule, Verdict};

/// The CEL standard-library environment, built once and shared.
///
/// [`Context::default`] builds `Arc::new(Env::stdlib())` on every call —
/// registering the whole standard library — and `eval_program` runs once per
/// endpoint-matching rule per request, twice for a rule that reaches
/// [`pii_caused`]. Paying for the stdlib there put ~31µs of setup in front of
/// ~1µs of evaluation and made the decision path scale with rule count rather
/// than with work. The environment is immutable and identical for every
/// evaluation, so it is built once and each context takes an `Arc` clone of it.
fn stdlib_env() -> Arc<Env> {
    static ENV: OnceLock<Arc<Env>> = OnceLock::new();
    ENV.get_or_init(|| Arc::new(Env::stdlib())).clone()
}

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
    decide_with(policy, facts, PiiWeight::Decides)
}

/// Decide the [`Outcome`] for `facts` with PII findings held back from
/// enforcement — the decision detect mode acts on.
///
/// Detect mode promises that content scanning never blocks; it is not a bypass
/// for the rest of the policy. So a rule that fires *only because* the request
/// carried PII is skipped and evaluation continues with the remaining rules,
/// while a rule that matches on endpoint, Kubernetes, SQL, or HTTP-metadata
/// facts still decides. The verdict the skipped rule would have produced stays
/// visible through [`decide_explained`], which callers audit as the would-be.
///
/// The attribution is per rule: a rule is PII-caused when it matches the real
/// facts but would not match with the PII summary cleared. That is what
/// separates a verdict PII *produced* from one that merely came after a rule
/// reading PII — an `endpoints`-bound deny preceded by `pii.count == 0 -> allow`
/// is enforced here, because the deny itself never consulted the summary.
///
/// An [`Allow`](Verdict::Allow) is held back only once something else already
/// has been. An exemption the policy really reached — `pii.count > 0 &&
/// pii.max_severity < 3 -> allow`, say — still stands, so **a request block mode
/// allows is allowed here too**. Past a held-back verdict the walk is answering
/// what the policy says with the scanner quiet, and a rule that owes its own
/// match to PII cannot grant an exemption on that reading: block mode never
/// reached it either.
///
/// That guarantee is about `Allow`, not about severity in general. Skipping a
/// PII-caused `Pause` can let a later non-PII `Deny` decide, so for the same
/// facts detect mode can return a *stricter* verdict than block mode. That deny
/// is the policy's own answer for the facts detect mode acts on, and it is the
/// answer the pre-attribution implementation gave too.
pub fn decide_pii_audit_only(policy: &Policy, facts: &Facts) -> Outcome {
    decide_with(policy, facts, PiiWeight::AuditsOnly)
}

/// How much say the PII summary has in the enforced verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiiWeight {
    /// PII findings decide like any other fact (block mode).
    Decides,
    /// PII findings are recorded, never enforced (detect mode).
    AuditsOnly,
}

fn decide_with(policy: &Policy, facts: &Facts, pii_weight: PiiWeight) -> Outcome {
    // Set once a verdict has been held back. From there on the walk is asking
    // what the policy says with the scanner quiet, so a later rule that owes
    // its own match to PII cannot answer either — an allow included. Honouring
    // one would grant an exemption the policy never issued (block mode stopped
    // at the held-back rule above it) and end the walk before the endpoint,
    // Kubernetes and HTTP-metadata rules below it.
    let mut held_back = false;
    for rule in &policy.rules {
        if !endpoint_matches(&rule.endpoint, facts.endpoint.as_deref()) {
            continue;
        }
        // Looked up once and reused for the attribution check below, which
        // re-runs the very same condition.
        let Some(program) = program_for(policy, rule) else {
            continue;
        };
        if !eval_program(&program, facts, facts.pii.as_ref()) {
            continue;
        }
        if pii_weight == PiiWeight::AuditsOnly
            && (held_back || rule.verdict != Verdict::Allow)
            && pii_caused(&program, facts)
        {
            held_back = true;
            continue;
        }
        return Outcome {
            verdict: rule.verdict,
            rule: Some(rule.name.clone()),
        };
    }
    Outcome {
        verdict: egress_verdict(policy, facts),
        rule: None,
    }
}

/// Whether the PII summary is what made the matching rule match: its condition
/// fires on the real facts (the caller has already checked that) but not on the
/// same facts with the summary cleared.
fn pii_caused(program: &Program, facts: &Facts) -> bool {
    // Without a summary the real evaluation already ran against the empty
    // default, so no rule can owe its match to PII.
    facts.pii.is_some() && !eval_program(program, facts, None)
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

/// Rule conditions compiled ahead of evaluation, keyed by the condition text
/// they were compiled from.
///
/// [`Policy::from_yaml`](crate::Policy::from_yaml) fills one of these so
/// [`decide`] evaluates rather than compiles: the compile is CEL parsing, and
/// it used to run once per endpoint-matching rule per request. Once, not
/// twice — a rule that reaches [`pii_caused`] was already compiled a single
/// time and its `Program` reused for the attribution run, so it is
/// [`eval_program`] that runs twice there, never the compiler. What this
/// removes from the request path is that one parse per matching rule.
///
/// **Keyed by the condition text, not by rule position or name**, so the table
/// cannot serve a stale program. [`Rule::condition`](crate::Rule::condition) is
/// a public field an owner of the `Policy` may reassign at any time; an entry
/// here is by construction the program for that exact string, so a reassigned
/// condition misses the table and [`program_for`] compiles it, rather than
/// answering with the program for the condition the rule used to carry. That is
/// what separates this from the per-[`Rule`](crate::Rule) cache #167 declined —
/// there the cached program hung off the rule and outlived the string it came
/// from.
///
/// An entry is present for every condition [`CompiledConditions::compile`] was
/// given, including the ones that did not compile: `Some(None)` records "this
/// text was tried and failed". Since #191 that arm is transient on the load
/// path — [`Policy::from_yaml`](crate::Policy::from_yaml) reads it through
/// [`CompiledConditions::inert_rules`] and refuses the policy — so a `Policy`
/// that loaded holds a `Program` for every condition its rules carry.
#[derive(Clone, Default)]
pub(crate) struct CompiledConditions(HashMap<String, Option<Arc<Program>>>);

impl CompiledConditions {
    /// Compile every distinct condition in `rules`. Identical conditions share
    /// one entry, so the compiler is asked once per distinct expression rather
    /// than once per rule.
    ///
    /// Silent: it reports nothing about a condition that will not compile, it
    /// records the failure. Naming those rules is
    /// [`Policy::from_yaml`](crate::Policy::from_yaml)'s job, through
    /// [`CompiledConditions::inert_rules`] — since #191 it refuses the policy
    /// rather than warning, and a warning emitted on the way to a hard error
    /// that already names the same rules would only be noise.
    ///
    /// The dedup covers the **compile**, not the **accounting**. Two rules
    /// carrying one unusable condition are two inert rules and an operator
    /// fixing a policy needs both names, which is why `inert_rules` walks
    /// `rules` rather than the table's keys. That matches
    /// [`Policy::warn_undefined_endpoints`](crate::Policy) and
    /// `warn_shadowed_rules`: the loader accounts for "a rule of yours is
    /// inert" per rule, never per distinct cause.
    pub(crate) fn compile(rules: &[Rule]) -> Self {
        let mut compiled: HashMap<String, Option<Arc<Program>>> = HashMap::new();
        for rule in rules {
            compiled
                .entry(rule.condition.clone())
                .or_insert_with(|| compile_program(&rule.condition));
        }
        Self(compiled)
    }

    /// The rules whose conditions can never match, paired with their positions
    /// in `rules` and in rule order.
    ///
    /// This is what [`Policy::from_yaml`](crate::Policy::from_yaml) turns into
    /// [`Error::UncompilableRuleConditions`](crate::Error), so on a policy that
    /// loads it is empty by construction. It is separate from `compile` because
    /// the answer is per rule while the compile is per distinct condition, and
    /// because the caller needs the whole list to report it in one go.
    ///
    /// The index comes from here rather than from the caller so the pairing
    /// cannot drift: it is the position in the same slice the filter ran over.
    pub(crate) fn inert_rules<'a>(&self, rules: &'a [Rule]) -> Vec<(usize, &'a Rule)> {
        rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| self.get(&rule.condition).is_some_and(Option::is_none))
            .collect()
    }

    /// The entry for `condition`: `Some(Some(program))` compiled,
    /// `Some(None)` was tried and failed, `None` was never seen.
    fn get(&self, condition: &str) -> Option<&Option<Arc<Program>>> {
        self.0.get(condition)
    }

    /// How many distinct conditions the table holds. Test-facing.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for CompiledConditions {
    /// The compiled syntax trees are an implementation detail far larger than
    /// the policy that produced them, and [`Policy`](crate::Policy) derives
    /// `Debug`. Print the entry count, not the trees.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CompiledConditions")
            .field(&self.0.len())
            .finish()
    }
}

/// The compiled program for `rule`, from the policy's load-time table when it
/// is there and by compiling on the spot when it is not.
///
/// A table miss is not an error state, and there are two ways to get one. A
/// [`Policy`](crate::Policy) built in code rather than loaded carries an empty
/// table, so every rule misses. A loaded policy whose
/// [`Rule::condition`](crate::Rule::condition) has since been reassigned keeps
/// its table — every other rule still hits — and misses on that one key alone,
/// because the key is the old text. Either way the miss gets exactly the
/// behaviour `decide` gave before conditions were compiled at load, warning
/// included.
///
/// A **hit** on a recorded failure would decline the same way, and as of #191 no
/// `Policy` can present one. `Policy::compiled` is private and written in
/// exactly one place — `from_yaml`, which refuses the policy when
/// `inert_rules` is non-empty — and every other way to get a `Policy` (built
/// in code, deserialized, `Default`) leaves the table *empty*, which is a
/// miss, not a hit on a failure. So this is not an arm kept for some live
/// caller: there is none, and saying otherwise would be inventing a use case
/// for it.
///
/// It costs nothing to keep, because the arm is the table's own
/// `Option<Arc<Program>>` cloned through rather than a guard written for it.
/// What it buys is that a second writer of `compiled` — the invariant above is
/// one private field away from a future change, not a type-level guarantee —
/// meets the fail-closed answer here instead of a program that was never
/// compiled.
fn program_for(policy: &Policy, rule: &Rule) -> Option<Arc<Program>> {
    match policy.compiled_conditions().get(&rule.condition) {
        Some(compiled) => compiled.clone(),
        None => compile_condition(rule),
    }
}

/// Compile a rule condition. A condition that does not compile cannot match,
/// which keeps a malformed rule from turning a deny into an allow.
///
/// A **blank** condition is declined without reaching the compiler. That guard
/// began as a panic shield (#151) and is no longer one: on `cel` 0.14 every
/// input class #151 and #154 measured — blank, a syntax error, a lone
/// unlexable character ASCII or not, a lone invisible character — returns
/// `Err` rather than panicking. The test below named for that property pins
/// it. The guard survives on a smaller claim: blank is the malformed
/// condition an author writes by accident, and
/// `"condition is blank"` tells them more than `"failed to compile"` does.
///
/// [`Policy::from_yaml`](crate::Policy::from_yaml) already refuses to load a
/// policy carrying a **blank** condition, so that arm is not what an operator
/// meets; it is what `decide` owes a [`Policy`](crate::Policy) built in code,
/// which the public API accepts just the same. The two answers differ on
/// purpose: the loader is reading the author's file and says so loudly, while
/// here the rule declines like any other condition that cannot compile.
///
/// The **failed-compile** arm is likewise not what an operator meets. Since
/// #191 a policy carrying a condition that will not compile does not load at
/// all, so this arm answers the same two shapes the blank one does: a `Policy`
/// built in code, and a loaded policy whose [`Rule::condition`](crate::Rule)
/// was reassigned to something unusable after the load. Both miss the table
/// and land here, where the rule declines and the warning names it — there is
/// no file to point the author at in either case.
fn compile_condition(rule: &Rule) -> Option<Arc<Program>> {
    let program = compile_program(&rule.condition);
    if program.is_none() {
        warn_inert_rule(rule);
    }
    program
}

/// Compile a condition without saying anything about it.
///
/// The silent half of [`compile_condition`], and what
/// [`CompiledConditions::compile`] calls: the loader has to record a failure
/// without reporting it, because since #191 the report is
/// [`Policy::from_yaml`](crate::Policy::from_yaml)'s refusal, naming every
/// offending rule at once rather than one warning per condition compiled here.
fn compile_program(condition: &str) -> Option<Arc<Program>> {
    if crate::is_blank_condition(condition) {
        return None;
    }
    Program::compile(condition).ok().map(Arc::new)
}

/// Name a rule whose condition can never match, so an operator can find it.
///
/// Both arms name the rule rather than the condition alone: `condition` does
/// not identify which rule went inert — least of all on the blank arm, where it
/// is empty by definition — and a policy built in code has no file and line to
/// point at. This mirrors `warn_undefined_endpoints` and `warn_shadowed_rules`,
/// the loader's own two "a rule of yours is inert" warnings, which are likewise
/// per rule.
///
/// Kept apart from [`compile_condition`] so that what the two arms say stays
/// one concern and deciding whether to say it stays another. It is the
/// evaluation-time answer only: the loader refuses such a policy instead
/// (see [`Policy::validate_compiled_conditions`](crate::Policy)), so nothing
/// reaches here that an operator could have been told about at startup.
fn warn_inert_rule(rule: &Rule) {
    if crate::is_blank_condition(&rule.condition) {
        tracing::warn!(
            rule = %rule.name,
            "policy rule condition is blank; the rule cannot match"
        );
    } else {
        tracing::warn!(
            rule = %rule.name,
            condition = %rule.condition,
            "policy rule condition failed to compile"
        );
    }
}

/// Evaluate a compiled condition against the facts. Any error → `false` (no
/// match).
///
/// `pii` is the summary to bind, passed separately from `facts` so attribution
/// can re-run the same program with it cleared.
fn eval_program(program: &Program, facts: &Facts, pii: Option<&PiiFacts>) -> bool {
    // `Context::with_env` rather than `Context::default`: same standard library,
    // without rebuilding it per evaluation. See [`stdlib_env`].
    let mut ctx = Context::with_env(stdlib_env());
    if let Some(http) = &facts.http {
        if let Ok(value) = cel::to_value(http) {
            ctx.add_variable_from_value("http", value);
        }
    }
    if let Some(sql) = &facts.sql {
        if let Ok(value) = cel::to_value(sql) {
            ctx.add_variable_from_value("sql", value);
        }
    }
    if let Some(k8s) = &facts.k8s {
        if let Ok(value) = cel::to_value(k8s) {
            ctx.add_variable_from_value("k8s", value);
        }
    }
    // Always register `pii` (default = empty) so absence conditions like
    // `pii.count == 0` are expressible, not just `pii.count > 0`.
    let default_pii = PiiFacts::default();
    let resolved_pii = pii.unwrap_or(&default_pii);
    if let Ok(value) = cel::to_value(resolved_pii) {
        ctx.add_variable_from_value("pii", value);
    }

    match program.execute(&ctx) {
        Ok(value) => matches!(value, Value::Bool(true)),
        // A condition that errors at run time (indexing an empty `pii.types`,
        // say) is indistinguishable from one that legitimately said `false`,
        // and attribution reads that `false` as "PII caused this match" — so an
        // operator debugging a rule that never fires needs to see it. `debug`
        // rather than `warn`: referencing a fact this request does not carry is
        // an error by design (that is how a `sql` rule declines an HTTP
        // request), so this fires on ordinary traffic, not only on a bad rule.
        Err(error) => {
            tracing::debug!(%error, "policy rule condition failed to evaluate");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CompiledConditions;
    use crate::{Facts, HttpFacts, Policy, Rule, Verdict};

    fn domain_facts(domain: &str) -> Facts {
        Facts {
            domain: Some(domain.to_string()),
            ..Default::default()
        }
    }

    fn http_facts(method: &str) -> Facts {
        Facts {
            http: Some(HttpFacts {
                method: method.to_string(),
                ..Default::default()
            }),
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

    /// #151: a rule carrying a blank condition must decline like any other
    /// condition that cannot compile, not take the decision path down.
    ///
    /// `Policy::from_yaml` refuses to load such a policy at all, so this builds
    /// the `Policy` in code — the shape `decide` still has to answer for, since
    /// it accepts any `&Policy`.
    #[test]
    fn a_blank_condition_declines_instead_of_panicking() {
        // Unicode whitespace included: `trim` treats it as blank, so the guard
        // must too. On `cel` 0.14 `Program::compile` returns `Err` on it just as
        // it does on `""`, so what the guard buys here is the blank-specific
        // message, not a crash that would otherwise happen.
        for condition in ["", " ", "\n", "\t\r\n", "\u{00a0}", "\u{3000}"] {
            let policy = Policy {
                rules: vec![Rule {
                    name: "blank".into(),
                    endpoint: "*".into(),
                    condition: condition.to_string(),
                    verdict: Verdict::Allow,
                }],
                ..Default::default()
            };

            // The rule declines, so the egress default (deny) answers: the
            // blank condition can neither match nor crash.
            assert_eq!(
                super::decide(&policy, &Facts::default()),
                Verdict::Deny,
                "condition {condition:?}"
            );
        }
    }

    /// #154: the blank condition is one member of a much wider panicking set,
    /// and the rest never reach the guard above. `Program::compile` must answer
    /// for all of them the same way — an `Err` the caller can decline on.
    ///
    /// The classes are the ones #154 measured. Four of them are invisible in an
    /// editor and are *not* Unicode `White_Space`, so `is_blank_condition` does
    /// not — and deliberately should not — catch them: they are unlexable for
    /// the same reason `@` is, not because they are blank.
    ///
    /// Both halves are asserted. `decide` returning `Deny` alone would not
    /// pin this: `Deny` is also the egress default, so a parser that recovered
    /// `"&&"` into some non-true value would satisfy it while the property
    /// this test exists for — `Program::compile` returns, with an `Err` — had
    /// regressed. The compile assertion is the one that names that property;
    /// the decision assertion keeps the fail-closed path covered end to end.
    #[test]
    fn malformed_conditions_decline_instead_of_panicking() {
        let conditions = [
            // Syntax errors: a token sequence the grammar cannot close.
            "&&",
            ")",
            "'abc",
            "true &&",
            ".",
            "()",
            // A comment with no expression after it.
            "// nothing",
            // A lone ASCII character no token can start with.
            "@",
            "$",
            "#",
            ";",
            // The same, outside ASCII.
            "\u{00a7}",
            "\u{20ac}",
            "\u{1f600}",
            "\u{4e2d}",
            // The same, invisible: zero-width space, BOM, word joiner, soft
            // hyphen. These render as nothing and pass the blank guard.
            "\u{200b}",
            "\u{feff}",
            "\u{2060}",
            "\u{00ad}",
        ];

        for condition in conditions {
            // The property #154 is closed on: it returns, and it returns `Err`.
            assert!(
                super::Program::compile(condition).is_err(),
                "condition {condition:?} unexpectedly compiled"
            );

            let policy = Policy {
                rules: vec![Rule {
                    name: "malformed".into(),
                    endpoint: "*".into(),
                    condition: condition.to_string(),
                    verdict: Verdict::Allow,
                }],
                ..Default::default()
            };

            // Same contract as the blank case: the rule goes inert, so the
            // egress default (deny) answers. Failing closed, not crashing.
            assert_eq!(
                super::decide(&policy, &Facts::default()),
                Verdict::Deny,
                "condition {condition:?}"
            );
        }
    }

    /// #167: a loaded policy carries its conditions already compiled, so
    /// `decide` looks a program up instead of parsing CEL once per
    /// endpoint-matching rule per request (twice for one that reaches
    /// attribution).
    ///
    /// Structural rather than behavioural on purpose. Compiling at load is
    /// meant to be invisible in what `decide` answers — the tests around this
    /// one are the guard on that — so the only thing left to pin is that the
    /// table the lookup reads is populated.
    ///
    /// The failed-compile entry is asserted against
    /// [`CompiledConditions::compile`] directly rather than through a loaded
    /// policy: since #191 no policy carrying one loads, so `from_yaml` cannot
    /// hand back a table to look at. `compile` is the same call `from_yaml`
    /// makes, one step before it reads the failures and refuses — which is the
    /// only window in which a `Some(None)` entry exists at all.
    #[test]
    fn a_loaded_policy_compiles_each_distinct_condition_once_at_load() {
        let policy = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  - name: post\n    endpoint: '*'\n    condition: \"http.method == 'POST'\"\n    verdict: deny\n  - name: post-too\n    endpoint: '*'\n    condition: \"http.method == 'POST'\"\n    verdict: pause\n  - name: get\n    endpoint: '*'\n    condition: \"http.method == 'GET'\"\n    verdict: allow\n",
        )
        .unwrap();

        // Three rules, two distinct conditions: the repeated expression is
        // compiled once and both rules read the same program.
        let compiled = policy.compiled_conditions();
        assert_eq!(compiled.len(), 2);
        assert!(matches!(
            compiled.get("http.method == 'POST'"),
            Some(Some(_))
        ));
        assert!(matches!(
            compiled.get("http.method == 'GET'"),
            Some(Some(_))
        ));

        // A condition that does not compile is *recorded* as failed rather
        // than left out. That is what `validate_compiled_conditions` reads to
        // name the rule and refuse the policy; it is asserted on a table this
        // test builds directly, because no `Policy` can carry one — `from_yaml`
        // is the only writer and it returns `Err` instead.
        let table = CompiledConditions::compile(&[Rule {
            name: "malformed".into(),
            endpoint: "*".into(),
            condition: "&&".into(),
            verdict: Verdict::Allow,
        }]);
        assert!(matches!(table.get("&&"), Some(None)));

        // A `Policy` built in code never passed through the loader, so it
        // carries no table and compiles where it always did.
        let built = Policy {
            rules: vec![Rule {
                name: "post".into(),
                endpoint: "*".into(),
                condition: "http.method == 'POST'".into(),
                verdict: Verdict::Deny,
            }],
            ..Default::default()
        };
        assert_eq!(built.compiled_conditions().len(), 0);
        assert_eq!(super::decide(&built, &http_facts("POST")), Verdict::Deny);
    }

    /// The optimization itself, pinned without a clock: `decide` resolves a
    /// loaded rule to the **same** `Program` every time, so it is reading the
    /// load-time table rather than parsing CEL again.
    ///
    /// `Arc::ptr_eq` is what makes this checkable. Recompiling is
    /// deterministic — a fresh parse of the same text answers every verdict
    /// identically — so no assertion about a `Verdict` can tell a table hit
    /// from a silent fallback to compiling, and every other test here would
    /// stay green if `program_for` stopped consulting the table entirely.
    /// Pointer identity can tell them apart, and the code-built policy below
    /// is the control: with no table it compiles afresh each call, and the
    /// pointers differ.
    #[test]
    fn decide_resolves_a_loaded_rule_to_the_same_program_every_time() {
        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: post\n    endpoint: '*'\n    condition: \"http.method == 'POST'\"\n    verdict: deny\n",
        )
        .unwrap();
        let rule = &policy.rules[0];

        let first = super::program_for(&policy, rule).expect("condition compiles");
        let second = super::program_for(&policy, rule).expect("condition compiles");
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "a loaded policy must hand out the program it compiled at load, not a fresh one"
        );

        // Control: no table, so each lookup compiles its own program.
        let built = Policy {
            rules: vec![Rule {
                name: "post".into(),
                endpoint: "*".into(),
                condition: "http.method == 'POST'".into(),
                verdict: Verdict::Deny,
            }],
            ..Default::default()
        };
        let built_rule = &built.rules[0];
        let a = super::program_for(&built, built_rule).expect("condition compiles");
        let b = super::program_for(&built, built_rule).expect("condition compiles");
        assert!(
            !std::sync::Arc::ptr_eq(&a, &b),
            "a policy with no table has nothing to reuse and must compile per call"
        );
    }

    /// Two rules carrying the same unusable condition are two inert rules, and
    /// the loader accounts for both — while still asking the compiler only
    /// once, which is the dedup #167 is for. Deduping the *accounting* along
    /// with the compile would leave the second rule unnamed and its author
    /// fixing the policy twice.
    ///
    /// This asserts `inert_rules` against the table `compile` builds. What the
    /// loader does with that set is #191's, and
    /// `lib::tests::names_every_rule_whose_condition_does_not_compile` asserts
    /// it end to end through the error `from_yaml` returns; the pair here is
    /// the unit underneath it, so a regression to per-condition accounting is
    /// caught on the side that computes it as well as the side that reports
    /// it.
    #[test]
    fn both_rules_sharing_an_unusable_condition_are_accounted_inert() {
        let rules = [
            Rule {
                name: "first".into(),
                endpoint: "*".into(),
                condition: "&&".into(),
                verdict: Verdict::Allow,
            },
            Rule {
                name: "second".into(),
                endpoint: "*".into(),
                condition: "&&".into(),
                verdict: Verdict::Allow,
            },
        ];
        let compiled = CompiledConditions::compile(&rules);

        // Both rules are named, in rule order and with their own positions —
        // not just the first one to reach the compiler.
        let inert: Vec<(usize, &str)> = compiled
            .inert_rules(&rules)
            .iter()
            .map(|(index, rule)| (*index, rule.name.as_str()))
            .collect();
        assert_eq!(inert, [(0, "first"), (1, "second")]);

        // One shared entry for the one distinct condition: the compiler was
        // asked once, which is what the dedup buys.
        assert_eq!(compiled.len(), 1);

        // And such a rule is genuinely inert, so a `Policy` carrying one —
        // which the loader now refuses, but the public API still accepts —
        // cannot turn the deny default into the allow it asks for.
        let policy = Policy {
            egress: crate::Egress {
                default: Verdict::Deny,
                ..Default::default()
            },
            rules: rules.to_vec(),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &Facts::default()), Verdict::Deny);
    }

    /// The load-time table is keyed by the condition *text*, so a
    /// [`Rule::condition`](crate::Rule::condition) reassigned after the load
    /// misses it and is compiled afresh rather than answered with the program
    /// its old text produced.
    ///
    /// This is the staleness #167 declined a per-`Rule` cache over: there the
    /// compiled program hung off the rule and outlived the string it came
    /// from. `condition` is a public field, so nothing stops an owner of the
    /// `Policy` from doing this.
    #[test]
    fn a_reassigned_condition_decides_on_its_new_text() {
        let mut policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: method\n    endpoint: '*'\n    condition: \"http.method == 'POST'\"\n    verdict: deny\n",
        )
        .unwrap();

        assert_eq!(super::decide(&policy, &http_facts("POST")), Verdict::Deny);
        assert_eq!(super::decide(&policy, &http_facts("GET")), Verdict::Allow);

        policy.rules[0].condition = "http.method == 'GET'".into();

        // The program compiled at load would still deny POST and let GET
        // through. The rule's current text is what decides.
        assert_eq!(super::decide(&policy, &http_facts("POST")), Verdict::Allow);
        assert_eq!(super::decide(&policy, &http_facts("GET")), Verdict::Deny);
    }

    /// #191: a policy carrying a malformed condition does not load at all, so
    /// the sound rule beneath it never gets to decide either — a refused
    /// policy is no policy, not a policy minus one rule.
    ///
    /// That is the cost the change accepts, and the one an operator has to
    /// know about: the gateway that started yesterday with an inert rule stops
    /// starting today. It buys the rule being *found*, rather than looking
    /// active in the file while answering nothing. Fix the condition and both
    /// rules decide, which is the second half of this test.
    #[test]
    fn a_condition_that_does_not_compile_fails_the_load_for_the_whole_policy() {
        let error = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  - name: broken\n    endpoint: '*'\n    condition: \"&&\"\n    verdict: allow\n  - name: sound\n    endpoint: '*'\n    condition: \"http.method == 'GET'\"\n    verdict: allow\n",
        )
        .expect_err("a condition that fails to compile is a load failure");
        assert!(
            matches!(&error, crate::Error::UncompilableRuleConditions { rules }
                if rules.len() == 1 && rules[0].name == "broken"),
            "unexpected error: {error}"
        );

        // The same policy with the broken condition repaired: both rules load
        // and decide, and the deny default still answers a request neither
        // matches.
        let policy = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  - name: broken\n    endpoint: '*'\n    condition: \"http.method == 'POST'\"\n    verdict: allow\n  - name: sound\n    endpoint: '*'\n    condition: \"http.method == 'GET'\"\n    verdict: allow\n",
        )
        .expect("every condition compiles");
        assert_eq!(super::decide(&policy, &http_facts("POST")), Verdict::Allow);
        assert_eq!(super::decide(&policy, &http_facts("GET")), Verdict::Allow);
        assert_eq!(super::decide(&policy, &Facts::default()), Verdict::Deny);
    }

    /// A table entry that records a failed compile declines, rather than
    /// matching or panicking.
    ///
    /// Since #191 no `Policy` reaches this state on its own: `compiled` is
    /// private, `from_yaml` is its only writer, and it returns `Err` instead of
    /// a policy holding a recorded failure. So this test writes the table by
    /// hand, which is the one thing that can reach the arm — and the reason to
    /// pin it is exactly that nothing else does. `program_for`'s doc says the
    /// arm is kept so a second writer of `compiled` would meet the fail-closed
    /// answer here; without this, that is a claim about untested code, and a
    /// later change that added such a writer would find out at runtime.
    #[test]
    fn a_recorded_compile_failure_in_the_table_declines() {
        let mut policy = Policy {
            egress: crate::Egress {
                default: Verdict::Deny,
                ..Default::default()
            },
            rules: vec![Rule {
                name: "malformed".into(),
                endpoint: "*".into(),
                condition: "&&".into(),
                verdict: Verdict::Allow,
            }],
            ..Default::default()
        };
        policy.compiled = CompiledConditions::compile(&policy.rules);

        // The table hits — this is the arm, not the miss arm the code-built
        // policies elsewhere in this file exercise.
        assert!(matches!(policy.compiled_conditions().get("&&"), Some(None)));
        assert!(super::program_for(&policy, &policy.rules[0]).is_none());

        // And the rule cannot turn the deny default into the allow it asks for.
        assert_eq!(super::decide(&policy, &Facts::default()), Verdict::Deny);
    }

    /// The proxy shares one `Policy` across connection tasks (`Arc<Policy>` in
    /// `GatewayState`), so the compiled programs it now carries have to cross
    /// threads with it.
    #[test]
    fn a_policy_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Policy>();
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

    /// A policy that exempts clean traffic before an `endpoints`-bound deny.
    /// The deny reads only Kubernetes facts, so detect mode enforces it: the
    /// allow-clean rule failing to match is not the same as PII causing the
    /// deny (regression for the residual left by #88).
    #[test]
    fn endpoint_deny_after_an_allow_clean_rule_survives_pii_audit_only() {
        use crate::{K8sFacts, detect_pii};

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: allow-clean\n    endpoint: '*'\n    condition: \"pii.count == 0\"\n    verdict: allow\n  \
             - name: k8s-no-secret-delete\n    endpoint: k8s-prod\n    condition: \"k8s.resource == 'secrets' && k8s.verb == 'delete'\"\n    verdict: deny\n",
        )
        .unwrap();

        let leak = Facts {
            endpoint: Some("k8s-prod".into()),
            k8s: Some(K8sFacts {
                verb: "delete".into(),
                resource: "secrets".into(),
                ..Default::default()
            }),
            pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
            ..Default::default()
        };
        // With findings the allow-clean rule cannot match, so the deny wins —
        // and it stands with PII held back, because it never read the summary.
        assert_eq!(super::decide(&policy, &leak), Verdict::Deny);
        assert_eq!(
            super::decide_pii_audit_only(&policy, &leak).verdict,
            Verdict::Deny
        );

        // A clean body takes the exemption in both readings.
        let clean = Facts {
            pii: None,
            ..leak.clone()
        };
        assert_eq!(super::decide(&policy, &clean), Verdict::Allow);
        assert_eq!(
            super::decide_pii_audit_only(&policy, &clean).verdict,
            Verdict::Allow
        );
    }

    /// The other half of the attribution: a verdict the summary *did* cause is
    /// held back, and the remaining rules still decide rather than the walk
    /// stopping at the skipped rule.
    #[test]
    fn pii_caused_verdict_is_held_back_and_later_rules_decide() {
        use crate::{K8sFacts, detect_pii};

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: block-pii\n    endpoint: '*'\n    condition: \"pii.count > 0\"\n    verdict: deny\n  \
             - name: review-prod-delete\n    endpoint: k8s-prod\n    condition: \"k8s.verb == 'delete'\"\n    verdict: pause\n",
        )
        .unwrap();

        let leak = Facts {
            endpoint: Some("k8s-prod".into()),
            k8s: Some(K8sFacts {
                verb: "delete".into(),
                resource: "secrets".into(),
                ..Default::default()
            }),
            pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
            ..Default::default()
        };
        let outcome = super::decide_explained(&policy, &leak);
        assert_eq!(outcome.verdict, Verdict::Deny);
        assert_eq!(outcome.rule.as_deref(), Some("block-pii"));

        let enforceable = super::decide_pii_audit_only(&policy, &leak);
        assert_eq!(enforceable.verdict, Verdict::Pause);
        assert_eq!(enforceable.rule.as_deref(), Some("review-prod-delete"));
    }

    /// An allow the policy really reached on the strength of a finding (a
    /// low-severity exemption) still stands, so a request block mode allows is
    /// allowed in detect mode too. The carve-out is for that case only — see
    /// `a_pii_caused_allow_behind_a_held_back_rule_does_not_mask_later_rules`
    /// for the ordering where an allow *is* held back.
    #[test]
    fn pii_caused_allow_is_not_held_back() {
        use crate::detect_pii;

        let policy = Policy::from_yaml(
            "egress:\n  default: deny\nrules:\n  \
             - name: allow-low-severity\n    endpoint: '*'\n    condition: \"pii.count > 0 && pii.max_severity < 3\"\n    verdict: allow\n",
        )
        .unwrap();

        let low = Facts {
            pii: detect_pii(r#"{"ip":"10.0.0.1"}"#),
            ..Default::default()
        };
        assert_eq!(super::decide(&policy, &low), Verdict::Allow);
        assert_eq!(
            super::decide_pii_audit_only(&policy, &low).verdict,
            Verdict::Allow
        );
    }

    /// An allow that only became reachable because a PII-caused verdict was
    /// held back is held back as well. Honouring it would let PII-shaped bytes
    /// in a request body suppress a deny that never read the summary — the very
    /// bypass this walk exists to prevent.
    #[test]
    fn a_pii_caused_allow_behind_a_held_back_rule_does_not_mask_later_rules() {
        use crate::{HttpFacts, detect_pii};

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: deny-high-severity-pii\n    endpoint: '*'\n    condition: \"pii.max_severity >= 3\"\n    verdict: deny\n  \
             - name: allow-any-pii\n    endpoint: '*'\n    condition: \"pii.count > 0\"\n    verdict: allow\n  \
             - name: deny-admin-api\n    endpoint: '*'\n    condition: \"http.path.startsWith('/admin')\"\n    verdict: deny\n",
        )
        .unwrap();

        let leak = Facts {
            http: Some(HttpFacts {
                method: "POST".into(),
                path: "/admin".into(),
                ..Default::default()
            }),
            pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
            ..Default::default()
        };
        // Block mode stops at the PII deny and never reaches the allow.
        assert_eq!(
            super::decide_explained(&policy, &leak).rule.as_deref(),
            Some("deny-high-severity-pii")
        );
        // So detect mode must not grant it either: the HTTP deny below decides.
        let enforceable = super::decide_pii_audit_only(&policy, &leak);
        assert_eq!(enforceable.verdict, Verdict::Deny);
        assert_eq!(enforceable.rule.as_deref(), Some("deny-admin-api"));
    }

    /// Held-back verdicts fall through to the egress lists when no later rule
    /// matches — the path the `continue` opened up, since the old walk always
    /// returned at its first match.
    #[test]
    fn a_held_back_verdict_falls_through_to_egress() {
        use crate::detect_pii;

        let rules = "rules:\n  \
             - name: pause-on-pii\n    endpoint: '*'\n    condition: \"pii.count > 0\"\n    verdict: pause\n";
        let leak = |domain: &str| Facts {
            domain: Some(domain.to_string()),
            pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
            ..Default::default()
        };

        // Default deny: the pause is held back, the default still enforces.
        let closed = Policy::from_yaml(&format!("egress:\n  default: deny\n{rules}")).unwrap();
        assert_eq!(
            super::decide_explained(&closed, &leak("api.example.com")).verdict,
            Verdict::Pause
        );
        let enforceable = super::decide_pii_audit_only(&closed, &leak("api.example.com"));
        assert_eq!(enforceable.verdict, Verdict::Deny);
        assert_eq!(enforceable.rule, None, "an egress decision names no rule");

        // Allow list: nothing is left to enforce once the pause is held back.
        let open = Policy::from_yaml(&format!(
            "egress:\n  default: deny\n  allow:\n    - api.example.com\n  deny:\n    - blocked.example.com\n{rules}"
        ))
        .unwrap();
        assert_eq!(
            super::decide_pii_audit_only(&open, &leak("api.example.com")).verdict,
            Verdict::Allow
        );
        // Deny list: an egress deny is not a PII verdict, so it is enforced.
        assert_eq!(
            super::decide_pii_audit_only(&open, &leak("blocked.example.com")).verdict,
            Verdict::Deny
        );
    }

    /// Attribution re-runs the whole condition, so a rule mixing PII with other
    /// facts is judged on whether it would still have fired without the summary:
    /// held back under `&&`, enforced under `||`.
    #[test]
    fn attribution_reads_compound_conditions_as_a_whole() {
        use crate::{K8sFacts, detect_pii};

        let delete_with_pii = |condition: &str| {
            let policy = Policy::from_yaml(&format!(
                "egress:\n  default: allow\nrules:\n  - name: guard\n    endpoint: '*'\n    condition: \"{condition}\"\n    verdict: deny\n"
            ))
            .unwrap();
            let facts = Facts {
                k8s: Some(K8sFacts {
                    verb: "delete".into(),
                    resource: "secrets".into(),
                    ..Default::default()
                }),
                pii: detect_pii(r#"{"user":{"rrn":"670125-1230644"}}"#),
                ..Default::default()
            };
            (
                super::decide(&policy, &facts),
                super::decide_pii_audit_only(&policy, &facts).verdict,
            )
        };

        // The deny needs the summary, so detect mode holds it back.
        assert_eq!(
            delete_with_pii("k8s.verb == 'delete' && pii.count > 0"),
            (Verdict::Deny, Verdict::Allow)
        );
        // The `k8s` disjunct fires on its own, so the deny stands.
        assert_eq!(
            delete_with_pii("k8s.verb == 'delete' || pii.count > 0"),
            (Verdict::Deny, Verdict::Deny)
        );
    }

    /// A body that was never scanned leaves `pii` unset, and the real walk
    /// already ran against the empty default — so nothing is attributable to
    /// PII and a deny is enforced unchanged.
    #[test]
    fn an_unscanned_body_attributes_nothing_to_pii() {
        use crate::K8sFacts;

        let policy = Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  \
             - name: k8s-no-secret-delete\n    endpoint: k8s-prod\n    condition: \"k8s.resource == 'secrets' && k8s.verb == 'delete'\"\n    verdict: deny\n",
        )
        .unwrap();

        let unscanned = Facts {
            endpoint: Some("k8s-prod".into()),
            k8s: Some(K8sFacts {
                verb: "delete".into(),
                resource: "secrets".into(),
                ..Default::default()
            }),
            pii: None, // oversized, non-text, or over-cap-decoded body
            ..Default::default()
        };
        assert_eq!(
            super::decide_pii_audit_only(&policy, &unscanned).verdict,
            Verdict::Deny
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
