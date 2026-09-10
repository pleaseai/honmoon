//! CodSpeed benchmarks for the honmoon-core policy engine.
//!
//! These cover the CPU-bound hot paths the proxy hits on every request:
//! policy parsing, protocol fact extraction (SQL / Kubernetes / PostgreSQL
//! wire), domain matching, and CEL-driven policy decisions.

use divan::{Bencher, black_box};
use honmoon_core::protocols::{parse_k8s_request, parse_postgres_query, parse_sql};
use honmoon_core::{
    Facts, HttpFacts, K8sFacts, Policy, SqlFacts, decide, decide_explained, decide_pii_audit_only,
    detect_pii, engine,
};

fn main() {
    divan::main();
}

/// The shipped example policy — representative of a real deployment.
const EXAMPLE_POLICY: &str = include_str!("../../../policies/agent.yaml");

/// A PII-gated deny ahead of an endpoint-bound one. The shipped policy has no
/// `pii` rules, so detect mode's attribution walk needs its own fixture.
const PII_ATTRIBUTION_POLICY: &str = "\
egress:
  default: allow
rules:
  - name: deny-high-severity-pii
    endpoint: '*'
    condition: \"pii.count > 0 && pii.max_severity >= 3\"
    verdict: deny
  - name: k8s-no-secret-delete
    endpoint: k8s-prod
    condition: \"k8s.resource == 'secrets' && k8s.verb == 'delete'\"
    verdict: deny
";

/// A checksum-valid RRN — a high-severity finding, as in the `pii` tests.
const RRN_BODY: &str = r#"{"user":{"rrn":"670125-1230644"}}"#;

// --- Policy parsing --------------------------------------------------------

#[divan::bench]
fn parse_policy_yaml() -> Policy {
    Policy::from_yaml(black_box(EXAMPLE_POLICY)).expect("valid policy")
}

// --- Protocol fact extraction ---------------------------------------------

#[divan::bench(args = [
    "SELECT * FROM public.orders WHERE id = 1",
    "DROP TABLE IF EXISTS users",
    "INSERT INTO logs (a) VALUES (1)",
    "UPDATE Users SET x = 1 WHERE id = 42",
])]
fn parse_sql_statement(bencher: Bencher, query: &str) {
    bencher.bench(|| parse_sql(black_box(query)));
}

#[divan::bench]
fn parse_postgres_wire_query(bencher: Bencher) {
    let body = b"DROP TABLE users;\0";
    let mut packet = vec![b'Q'];
    packet.extend_from_slice(&((4 + body.len()) as u32).to_be_bytes());
    packet.extend_from_slice(body);
    bencher.bench(|| parse_postgres_query(black_box(&packet)));
}

#[divan::bench(args = [
    "/api/v1/namespaces/prod/secrets/db-password",
    "/apis/apps/v1/namespaces/staging/deployments/api",
    "/api/v1/nodes",
])]
fn parse_k8s_path(bencher: Bencher, path: &str) {
    bencher.bench(|| parse_k8s_request(black_box("DELETE"), black_box(path)));
}

// --- Domain matching -------------------------------------------------------

#[divan::bench(args = [
    ("github.com", "github.com"),
    ("*.githubusercontent.com", "raw.githubusercontent.com"),
    ("*.internal.corp", "db.internal.corp"),
])]
fn match_domain(bencher: Bencher, case: (&str, &str)) {
    bencher.bench(|| engine::matches_domain(black_box(case.0), black_box(case.1)));
}

// --- End-to-end policy decisions ------------------------------------------

fn example_policy() -> Policy {
    Policy::from_yaml(EXAMPLE_POLICY).expect("valid policy")
}

#[divan::bench]
fn decide_egress_allow(bencher: Bencher) {
    let policy = example_policy();
    let facts = Facts {
        domain: Some("github.com".into()),
        ..Default::default()
    };
    bencher.bench(|| decide(black_box(&policy), black_box(&facts)));
}

#[divan::bench]
fn decide_egress_default_deny(bencher: Bencher) {
    let policy = example_policy();
    let facts = Facts {
        domain: Some("unknown.example.com".into()),
        ..Default::default()
    };
    bencher.bench(|| decide(black_box(&policy), black_box(&facts)));
}

#[divan::bench]
fn decide_cel_sql_rule(bencher: Bencher) {
    let policy = example_policy();
    let facts = Facts {
        endpoint: Some("postgres-prod".into()),
        sql: Some(SqlFacts {
            verb: "DROP".into(),
            table: "users".into(),
        }),
        ..Default::default()
    };
    bencher.bench(|| decide_explained(black_box(&policy), black_box(&facts)));
}

#[divan::bench]
fn decide_cel_k8s_rule(bencher: Bencher) {
    let policy = example_policy();
    let facts = Facts {
        endpoint: Some("k8s-prod".into()),
        k8s: Some(K8sFacts {
            verb: "delete".into(),
            resource: "secrets".into(),
            namespace: "prod".into(),
        }),
        ..Default::default()
    };
    bencher.bench(|| decide_explained(black_box(&policy), black_box(&facts)));
}

#[divan::bench]
fn decide_cel_http_rule(bencher: Bencher) {
    let policy = example_policy();
    let facts = Facts {
        http: Some(HttpFacts {
            method: "POST".into(),
            host: "api.example.com".into(),
            path: "/upload".into(),
            body_size: 20_971_520,
        }),
        ..Default::default()
    };
    bencher.bench(|| decide_explained(black_box(&policy), black_box(&facts)));
}

/// Detect mode's enforcement pass, which `mitm.rs` runs on every scanned
/// request whose verdict is not `Allow`: the PII deny is attributed per rule
/// (re-running its condition against a cleared summary) and held back, then the
/// endpoint-bound deny below it decides.
#[divan::bench]
fn decide_pii_audit_only_attributed_walk(bencher: Bencher) {
    let policy = Policy::from_yaml(PII_ATTRIBUTION_POLICY).expect("valid policy");
    let facts = Facts {
        endpoint: Some("k8s-prod".into()),
        k8s: Some(K8sFacts {
            verb: "delete".into(),
            resource: "secrets".into(),
            namespace: "prod".into(),
        }),
        pii: detect_pii(RRN_BODY),
        ..Default::default()
    };
    bencher.bench(|| decide_pii_audit_only(black_box(&policy), black_box(&facts)));
}
