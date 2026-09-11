---
name: hook-salt-audit-visibility-131
description: PR reviewed for issue #131 (hook falls back to public HMAC key) — the new audit-log reporting path's remaining gaps.
metadata:
  type: project
---

Reviewed the PR making `honmoon hook`'s fallback machine-key degradation visible via
`Decision::Degraded` audit events (crates/honmoon-cli/src/hook.rs `audit_machine_key_source`,
`record_machine_key_source`; crates/honmoon-core/src/audit.rs `Decision::Degraded`/`RedactionFacts`).

Design is sound for the case it targets (no audit log configured, or the audit file can't be
*opened*) — both fall back to a documented, intentional `eprintln!`, matching the module's
fail-open contract. **Not** in scope to flag per the user (explicitly deliberate): the fail-open
fallback itself, the public constant key, redaction continuing.

Two gaps found in the *reporting* path itself, not the fallback:
1. `AuditLog::record`'s sink-write failure (after the file opened fine) logs via `tracing::warn!`
   only. `honmoon-cli/src/main.rs` calls `tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init()`
   — with no `RUST_LOG` set (the default for a hook subprocess under an agent), `EnvFilter::from_default_env()`
   defaults to ERROR-level only, so this warn is dropped before it even reaches stderr. Even if it
   weren't filtered, it lands on stderr — the exact channel the PR's own docs say a non-interactive
   hook's output "reaches nobody." So a *post-open* sink write failure in the hook transport is
   silent, undermining the PR's central goal for that one failure mode.
2. Correlated failure: the same underlying condition that makes the persisted salt file
   unreadable/unwritable (disk full, permission change, `~/.honmoon` unwritable) can also make
   `AuditLog::with_file` fail to open the configured audit log, leaving only the stderr line as
   signal — in exactly the conditions most likely to trigger the fallback in the first place.

**Why this matters for future review:** if this file is touched again, check whether the sink-write
failure path routes anywhere durable for the hook transport specifically (a fresh short-lived
process, no ring to query later) — `tracing::warn!` to an ERROR-filtered, discarded-stderr sink is
not that.
