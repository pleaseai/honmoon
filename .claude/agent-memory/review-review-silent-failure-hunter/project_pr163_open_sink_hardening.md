---
name: pr163-open-sink-hardening
description: The audit sink's two call sites react to a refused open very differently — gateway fail-closed and loud, hook swallowed to a stderr nobody reads (#165)
metadata:
  type: project
---

`open_sink()` (`crates/honmoon-core/src/audit.rs`, #138/#163) refuses a symlinked final
path component and any non-regular target. The two call sites react to that refusal
asymmetrically, and the asymmetry is the thing to remember:

- **Gateway** (`honmoon-cli/src/main.rs`): `with_file(...).with_context(...)?` propagates
  to `main() -> Result<()>`, so the process exits nonzero with the full message. Fail-closed
  and loud — no gap. The context string names the regular-file constraint so the operator
  can act on it.
- **Hook** (`honmoon-cli/src/hook.rs`, `audit_machine_key_status`): swallows any
  `with_file`/write failure after a single `eprintln!`, deliberate per its own doc comment
  and reviewed in #131 (see [[project_hook_salt_audit_visibility_131]]). That stderr is a
  channel a non-interactive hook subprocess discards. The function only fires when the
  machine key is **already degraded**, so this is the one durable trace of the worst case.

That swallow is untouched by #163 — but the PR **widens the set of conditions that reach
it**: before, a symlink planted at the `--audit-log` path was followed and the record
landed somewhere; a FIFO blocked until the agent timed the hook out. Both are now refused,
so an actor who can write the audit directory can suppress the degradation record on
purpose. Still a net improvement — a followed symlink wrote the record where nobody reads
and a blocking FIFO cost the hook its whole timeout budget — but the trigger is cheaper to
reach deliberately.

**Status: tracked in #165**, which carries the options (distinguish a hostile-target
refusal from an ordinary open failure; a second durable channel; surface it in the hook's
JSON response) and notes it shares #161's "the event about the sink is written to that
sink" recursion. The hook flag's own `--help` text now says a refused path costs the
record. **Do not re-report this as an unnamed gap.**

`record` vs `record_durable` (the #131 fix) is unchanged by #163.
