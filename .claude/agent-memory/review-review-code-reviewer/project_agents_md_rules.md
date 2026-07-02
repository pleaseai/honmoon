---
name: project-agents-md-rules
description: Key crates/AGENTS.md rules to check on every Rust data-plane diff (honmoon-proxy, honmoon-core, honmoon-mgmt, honmoon-cli)
metadata:
  type: project
---

`crates/AGENTS.md` boundary table has three tiers — check the diff against all three, not just "Never":

- **Always**: `honmoon-core` stays transport-agnostic/I/O-free; fail-closed (default-deny, broken rule never allows); extract only declared protocol facts.
- **Ask first**: changing `decide()` precedence; changing the policy struct shape (synced to TS + JSON Schema, TD-001); **adding a new workspace dependency**. This last one is easy to miss — a PR that adds a crate to root `Cargo.toml` `[workspace.dependencies]` (or a crate's own `Cargo.toml` referencing `.workspace = true`) without prior discussion is a process violation worth flagging even though it compiles cleanly and passes clippy. Confidence ~80-85, severity important — it's a process/guideline flag, not a code defect.
- **Never**: add `tokio`/sockets/I/O deps to `honmoon-core`; decrypt or buffer full payloads beyond what a rule needs; weaken tests to pass.

**Why**: caught in review of PR for issue #12 (decompress gzip/deflate before PII inspection) — `flate2` was added as a new workspace dep without evidence of prior discussion.

**How to apply**: on every diff touching `Cargo.toml` (root or any crate's), check whether it adds a *new* dependency (not just bumping an existing one) and cross-reference against this "ask first" rule.

See also [[feedback-trust-the-header-regression-pattern]] for a specific bug this same PR introduced.
