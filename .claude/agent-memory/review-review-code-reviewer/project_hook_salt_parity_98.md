---
name: project-hook-salt-parity-98
description: PR #122 (hook_salt.rs, issue #98) — reviewed clean; documents the intentional wire-vs-hook salt divergence for future touches
metadata:
  type: project
---

PR #122 moved hook-salt derivation into `honmoon-core::hook_salt` (`derive_hook_salt` +
`hook_salt_context`, pin > payload `session_id` > `""`) so `honmoon hook` (process transport) and
`POST /api/hooks/claude-code` (http transport) mint byte-identical `<<hs:…>>` placeholders for one
secret in one session. Traced both call paths end to end (`crates/honmoon-cli/src/hook.rs`
`session_salt`, `crates/honmoon-cli/src/main.rs` `gateway()`, `crates/honmoon-mgmt/src/lib.rs`
`HookSalt::for_payload`) — confirmed parity, `cargo test`/`clippy -D warnings`/`fmt --check` all
clean.

**Intentional side effect worth remembering**: by default (`--hook-salt-context` unset) the http
hook endpoint now keys its salt on the payload's `session_id` (`HookSalt::PerSession`), while wire
redaction (TLS-terminated proxy traffic) still keys on the fixed gateway context (`"default"`).
Before this PR both were fixed on `"default"` and provably equal, enforced by an unconditional
assert in `AppState::with_hook_config`. That assert is now conditional on `hook_salt.pinned()`
being `Some` (i.e. only fires for `HookSalt::Fixed`) — a deliberate loosening, not a regression:
detokenization is a shared-`MappingStore` lookup by placeholder string, so it works regardless of
which salt minted the placeholder. The consequence is that a secret seen via wire interception and
the same secret seen via the http hook endpoint in the same session can now show *different*
placeholders under default settings — parity was narrowed from "hook agrees with wire" to "the two
hook transports agree with each other," which is what issue #98 actually asked for. Flag this only
if a future PR's stated goal is wire/hook parity; it is not a defect on its own.
