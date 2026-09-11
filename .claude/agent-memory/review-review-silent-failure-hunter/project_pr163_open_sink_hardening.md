---
name: pr163-open-sink-hardening
description: PR #163 (issue #138) open_sink() O_NOFOLLOW/regular-file hardening — attacker-plantable trigger now reaches the pre-existing hook stderr-swallow gap from #131.
metadata:
  type: project
---

Reviewed `crates/honmoon-core/src/audit.rs`'s new `open_sink()` (`AuditLog::with_file`): refuses a
symlinked final path component (`O_NOFOLLOW`) and any non-regular post-open target (FIFO via
`O_NONBLOCK` so it can't block the hook, char/block device via `fstat`), creates mode `0600`.
`main.rs`/`hook.rs` had **zero diff** in this PR — only `audit.rs` changed.

Verified both call sites' reaction to the new failure modes:
- Gateway (`main.rs:336`): `with_file(...).with_context(...)?` → propagates to `main() -> Result<()>`,
  process exits nonzero with the full message printed. Fail-closed, loud — good, no gap.
- Hook (`hook.rs:425` `audit_machine_key_status`): pre-existing, already-reviewed-in-#131 pattern
  (see [[project_hook_salt_audit_visibility_131]]) — swallows any `with_file`/write failure to a
  single `eprintln!`, deliberate per its own doc comment ("stderr usually reaches nobody" for a
  non-interactive hook subprocess). This PR does not touch that code, but *does* widen the set of
  conditions that trigger it: a symlink or FIFO planted at the operator's `--audit-log` path is now
  a failure `with_file` refuses, where before the open would have followed the symlink and still
  recorded *something*. `audit_machine_key_status` only fires when the machine key is **already
  degraded**, so this is the one durable trace of that worst case — an attacker who can write to
  the audit-log's directory can now suppress it entirely by planting a symlink/FIFO there, in
  addition to whatever they could already do.

Flagged this at moderate confidence (~55) as an amplification of the #131 gap rather than new
silent-failure code — the swallow itself is deliberate/reviewed; what's new is who can reach it and
how reliably. `record` vs `record_durable` split (issue #131 fix) is unchanged by this PR.
Symlinked-parent-directory and existing-file-mode-preservation limitations are explicitly
documented, tested, and tracked as separate issues (#160, #161) — correctly handled, not gaps.
