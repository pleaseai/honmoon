---
name: pr122-hook-salt-parity
description: 'PR #122 (issue #98) hook-salt parity fix — README + rustdoc verified accurate against hook_salt.rs/HookSalt, zero findings; a calibration point for clean PRs'
metadata:
  type: project
---

PR #122 unified the Claude Code hook salt derivation (`honmoon-core::hook_salt`, `HookSalt` enum
in honmoon-mgmt, `hook::machine_key` in honmoon-cli) so the `process` and `http` transports mint
identical `<<hs:…>>` placeholders per session, and rewrote the "Both layers run at once" section
of `packages/claude-plugin/README.md` accordingly.

Verified accurate against code: CLI precedence (`--salt-context` > `HONMOON_HOOK_SALT_CONTEXT`
env > payload `session_id` > `""`) matches `hook.rs::session_salt` and `hook_salt.rs::
hook_salt_context`; the gateway's `--hook-salt-context` pin correctly ties the hook endpoint to
`HookSalt::Fixed` sharing wire redaction's salt, while unset ties it to `HookSalt::PerSession`;
losing `default_value = "default"` is a real behavior change but is documented in the flag's own
doc comment, including that wire redaction still falls back to `"default"`. No stale docs
elsewhere (README.md, docs/, wiki/llms-full.txt, .claude/skills/run-honmoon/SKILL.md) still
describe the old divergence — `SKILL.md`'s `--salt-context demo` example remains valid syntax.

Result: 0 findings. Same calibration signal as [[adr_0006_signed_header_amendment]] — this
author's PRs in this repo tend to have doc/code parity already verified before review.
