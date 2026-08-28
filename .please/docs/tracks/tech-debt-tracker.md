# Tech Debt Tracker

> Tracked across all tracks. Updated during implementation and retrospectives.

## Active

| ID | Source Track | Description | Priority | Created |
|----|------------|-------------|----------|---------|
| TD-001 | (scaffold) | Policy model is duplicated between Rust (`honmoon-core`) and TS (`@honmoon/policy`); consider generating both from the JSON Schema as a single source of truth | Medium | 2026-06-20 |
| TD-002 | (scaffold) | `serde_yaml` is deprecated; evaluate `serde_yaml_ng` or `serde_yml` | Low | 2026-06-20 |
| TD-003 | phase-1-http-egress-mvp | Linux (#36) and macOS (#69) implemented for an **unprivileged** child (ADR-0005: empty user+network namespace with the proxy bridged over a Unix socket; Seatbelt profile under `sandbox-exec`). root/CAP_SYS_ADMIN still bypass both, and run downgrades to advisory (fail-open) when the namespace is refused or the profile will not compile; every other platform still only sets proxy env vars, so a child that ignores them bypasses policy there | Medium | 2026-06-20 |
| TD-004 | phase-1-http-egress-mvp | CONNECT proxy sees only the host (SNI/authority); body/path rules require TLS termination (Phase 2). Document that HTTPS rules are host-level only for now | Medium | 2026-06-20 |
| TD-005 | phase-1-http-egress-mvp | CI actions are pinned to tags (`@v4`/`@stable`), not commit SHAs (flagged by CodeRabbit). Pin all GitHub Actions to full SHAs for supply-chain hardening, repo-wide, in one pass | Low | 2026-06-20 |
| TD-006 | phase-3-sql-k8s-parsers | SQL/K8s parsers (`honmoon-core::protocols`) are engine-complete and unit-tested but not fed by a live socket. Needs an inline TCP relay mode with per-endpoint listener config (postgres) and TLS termination (k8s HTTPS) to populate facts from real traffic | High | 2026-06-21 |

## Resolved

| ID | Source Track | Description | Resolved In | Date |
|----|------------|-------------|-------------|------|
