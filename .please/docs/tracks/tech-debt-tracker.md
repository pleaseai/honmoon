# Tech Debt Tracker

> Tracked across all tracks. Updated during implementation and retrospectives.

## Active

| ID | Source Track | Description | Priority | Created |
|----|------------|-------------|----------|---------|
| TD-001 | (scaffold) | Policy model is duplicated between Rust (`honmoon-core`) and TS (`@honmoon/policy`); consider generating both from the JSON Schema as a single source of truth | Medium | 2026-06-20 |
| TD-002 | (scaffold) | `serde_yaml` is deprecated; evaluate `serde_yaml_ng` or `serde_yml` | Low | 2026-06-20 |

## Resolved

| ID | Source Track | Description | Resolved In | Date |
|----|------------|-------------|-------------|------|
