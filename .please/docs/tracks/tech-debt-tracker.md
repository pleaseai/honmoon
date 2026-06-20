# Tech Debt Tracker

> Tracked across all tracks. Updated during implementation and retrospectives.

## Active

| ID | Source Track | Description | Priority | Created |
|----|------------|-------------|----------|---------|
| TD-001 | (scaffold) | Policy model is duplicated between Rust (`honmoon-core`) and TS (`@honmoon/policy`); consider generating both from the JSON Schema as a single source of truth | Medium | 2026-06-20 |
| TD-002 | (scaffold) | `serde_yaml` is deprecated; evaluate `serde_yaml_ng` or `serde_yml` | Low | 2026-06-20 |
| TD-003 | phase-1-http-egress-mvp | `honmoon run` only sets proxy env vars; a child that ignores them bypasses policy. Needs real network isolation (netns / NetworkExtension) to be enforcing rather than advisory | High | 2026-06-20 |
| TD-004 | phase-1-http-egress-mvp | CONNECT proxy sees only the host (SNI/authority); body/path rules require TLS termination (Phase 2). Document that HTTPS rules are host-level only for now | Medium | 2026-06-20 |
| TD-005 | phase-1-http-egress-mvp | CI actions are pinned to tags (`@v4`/`@stable`), not commit SHAs (flagged by CodeRabbit). Pin all GitHub Actions to full SHAs for supply-chain hardening, repo-wide, in one pass | Low | 2026-06-20 |

## Resolved

| ID | Source Track | Description | Resolved In | Date |
|----|------------|-------------|-------------|------|
