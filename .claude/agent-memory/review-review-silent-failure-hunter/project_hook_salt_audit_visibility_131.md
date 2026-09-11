---
name: hook-salt-audit-visibility-131
description: PR for issue #131 (hook falls back to public HMAC key) — the Degraded audit path is sound at open-failure and the post-open sink-write silence was fixed before merge by record_durable, but the correlated-failure gap stands; `tracing::warn!` is not a reporting channel in a short-lived subprocess
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

Two gaps found in the *reporting* path itself, not the fallback. **Gap 1 was fixed before merge;
gap 2 stands.**

1. **FIXED in #137 — do not re-report.** `AuditLog::record` reported a post-open sink-write
   failure through `tracing::warn!` and swallowed it. With no `RUST_LOG` set (the default for a
   hook subprocess under an agent), `EnvFilter::from_default_env()` defaults to ERROR, so the warn
   was dropped before any writer saw it — and even unfiltered it lands on stderr, the exact
   channel the PR's own docs say a non-interactive hook's output "reaches nobody". The merged code
   splits the write out: `AuditLog::record_durable` returns the sink result, `record` keeps the
   old warn-and-continue behaviour for every existing caller, `record_machine_key_source`
   (`hook.rs:270`) returns that result, and `audit_machine_key_source` (`hook.rs:315`) reports a
   refused sink with `eprintln!` (`hook.rs:330`). **The durable lesson: `tracing::warn!` is
   not a reporting channel in a short-lived subprocess.** No `RUST_LOG`, no ring to query afterwards, and stderr
   discarded — a warn there is indistinguishable from doing nothing. A one-shot process must hand
   the failure back to its caller.
2. Correlated failure: the same underlying condition that makes the persisted salt file
   unreadable/unwritable (disk full, permission change, `~/.honmoon` unwritable) can also make
   `AuditLog::with_file` fail to open the configured audit log, leaving only the stderr line as
   signal — in exactly the conditions most likely to trigger the fallback in the first place.

**Why this matters for future review:** if this file is touched again, check whether the sink-write
failure path routes anywhere durable for the hook transport specifically (a fresh short-lived
process, no ring to query later) — `tracing::warn!` to an ERROR-filtered, discarded-stderr sink is
not that.
