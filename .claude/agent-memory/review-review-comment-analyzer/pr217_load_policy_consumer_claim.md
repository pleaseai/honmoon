---
name: pr217-load-policy-consumer-claim
description: "A doc comment that says who consumes a returned value is checked by following the value to its route, not by recognising the subsystem — PR #217 said load_policy returns the source for the Claude Code hook endpoint when honmoon-mgmt serves it on GET /api/policy for the dashboard"
metadata:
  type: project
---

`crates/honmoon-cli/src/main.rs`'s `load_policy` returns `(Policy, String)` since #202 (PR #217),
and its doc justifies the second element by naming its consumer. The named consumer was wrong
(**corrected in PR #217 before merge** — the doc now names `GET /api/policy` and says outright that
nothing on the hook endpoint reads `policy_yaml`, so do not re-report this as live):
the `String` reaches `honmoon_mgmt::AppState::with_hook_config` as `policy_yaml`, and the only
read of that field is `get_policy` → `GET /api/policy`, which `apps/dashboard/src/api.ts`
fetches. `POST /api/hooks/claude-code` (`claude_code_hook`) never touches it — it uses
`hook_salt` and `hook_mappings`. The confusion is structural: the value is *passed through the
constructor named `with_hook_config`*, so "hook" is right there beside it while the actual route
is a different one.

**How to apply:** when a comment says a returned or stored value exists "because X needs it",
grep every read of the field (not the writes, and not the constructor's name) and land on the
route or function that consumes it. `AppState`'s own field doc already said the truth ("for the
dashboard's read-only policy view/editor") — a cheap cross-check when the consumer lives in
another crate.

The rest of #217's prose held up under tracing, including the parts that read as most exposed:
only three `load_policy` callers exist and no other policy read remains in the crate
(`run`, `gateway`, `policy_validate`); `serde_yaml` really does fold a multi-line plain scalar
into one `Value::String` (so the PEM fixture arrives entire, verified by parsing it); a
top-level YAML *sequence* is refused by `Policy::from_yaml` too (serde_yaml does not offer a
struct-from-seq path, so the "no verdict moves" claim survives the obvious counterexample); and
`gateway` does resolve the management token before reading the policy, which is what the
`#[cfg(unix)]` gate on the gateway arm is for. See [[pr201-policy-validate-claims]] for the
earlier round on the same function.
