# Honmoon Claude Code plugin — secret/PII redaction

Client-side [Claude Code hooks](https://code.claude.com/docs/en/hooks) that keep
secrets and sensitive identifiers out of what Claude Code persists **locally**.

## Why this exists (and how it relates to the proxy)

Honmoon's proxy covers the **wire**: agent clients resend the full conversation
each turn, so every secret re-crosses the proxy and is re-redacted — the model
and provider never see a raw secret. What the proxy *cannot* reach is what the
client writes to disk **before** sending: Claude Code stores raw prompts and raw
`Read` output in its session transcript
(`~/.claude/projects/<project>/<session-id>.jsonl`), which then feeds `/resume`,
compaction summaries, subagents, and any backup/sync of that directory.

This plugin closes that gap at the client. It is complementary to the proxy, not
a replacement:

- **Proxy** = enforcement backstop (agent-agnostic, catches everything on the wire).
- **Plugin** = lightweight onboarding (no local CA trust needed) + transcript
  hygiene (plaintext is redacted before it can land on disk).

## What the hooks do

| Hook | Event | Behavior |
|------|-------|----------|
| Redact tool output | `PostToolUse` (`Read`) | Scans the tool result and replaces every detected secret/PII surface with a stable placeholder via `updatedToolOutput`, so the redacted form is what enters the model context. |
| Block risky prompts | `UserPromptSubmit` | A hook **cannot** rewrite a prompt, so a prompt carrying a secret (or a high-severity identifier like an RRN) is **blocked** with an actionable reason. Remove the value and resubmit. |
| Deny sensitive reads | `PreToolUse` (`Read`) | Denies reads of known credential/key files (`.env*`, `*.pem`, `*.key`, `id_rsa`/`id_ed25519`, `~/.aws/credentials`, …) before the file is opened — so their plaintext never reaches the transcript. Template files (`.env.example`) are allowed. |

All three call the same engine (`honmoon hook`), which reuses the exact Tier-1
detectors and reversible tokenizer the proxy uses (`honmoon-core`). Placeholders
are byte-stable for a given secret within a session, so re-redacting resent
history keeps a provider's prompt cache intact.

## Requirements

The plugin is a thin shell around the `honmoon` binary — install it and put it
on `PATH`:

```sh
cargo install --path crates/honmoon-cli   # from a checkout of the honmoon repo
# or: cargo build --release  &&  add target/release to PATH
honmoon --help                            # sanity check
```

If `honmoon` is **not** found, every hook is a deliberate no-op (it exits 0 with
no output): the tool call / prompt proceeds unredacted and the proxy remains the
backstop. Point the hooks at a specific binary with the `HONMOON_BIN` env var.

## Install the plugin

Install from the repo's plugin marketplace, or point Claude Code at this
directory (`packages/claude-plugin/`) as a local plugin. See
[Claude Code plugins](https://code.claude.com/docs/en/plugins). Once installed,
`/hooks` should list the three honmoon hooks.

## Verify

```sh
# Redacts an Anthropic key in Read output → updatedToolOutput with a placeholder:
printf '{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":"API_KEY=sk-ant-api03-cache-stable-abcDEF123456"}' | honmoon hook

# Denies a Read of .env:
printf '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/proj/.env"}}' | honmoon hook

# Blocks a prompt carrying a secret:
printf '{"hook_event_name":"UserPromptSubmit","prompt":"deploy with sk-ant-api03-cache-stable-abcDEF123456"}' | honmoon hook
```

## Known limitation — the transcript

`PostToolUse` `updatedToolOutput` is documented to replace what the **model**
sees. The docs do **not** explicitly guarantee that the persisted transcript
`.jsonl` is rewritten with the redacted value. For files that are *known*
credential stores, the guaranteed transcript-hygiene path is therefore the
`PreToolUse` deny (the file is never read, so nothing is transcribed). For a
secret that merely appears inside an otherwise-normal file, `PostToolUse` at
minimum keeps the raw secret out of the model context; whether it also scrubs
the transcript depends on the Claude Code version — verify against yours.

## Scope

This ships the **command transport** (works with only the binary installed). A
gateway-direct HTTP transport (`type: "http"` hooks posting to the honmoon
management API, sharing the tokenization mapping with a co-running proxy) is a
planned follow-up. HTTP hooks fail open, so it will not become the silent
default.
