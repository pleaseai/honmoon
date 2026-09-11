# Honmoon Claude Code plugin — secret/PII redaction

Client-side [Claude Code hooks](https://code.claude.com/docs/en/hooks) that keep
secrets and sensitive identifiers out of what Claude Code persists **locally**.

## Why this exists (and how it relates to the proxy)

Honmoon's proxy covers the **wire**: agent clients resend the full conversation
each turn, so a secret the proxy detects is re-redacted on every turn — the model
and provider see the placeholder, not the raw value. What the proxy *cannot*
reach is what the client writes to disk **before** sending: Claude Code stores
raw prompts and raw tool output in its session transcript
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
| Redact tool output | `PostToolUse` (`Read`, `Bash`, `Grep`) | Scans the tool result and replaces every detected secret/PII surface with a stable placeholder via `updatedToolOutput`, so the redacted form is what enters the model context. `Bash` and `Grep` are matched too, not just `Read`: a secret surfaced by `cat`/`grep`/`echo` lands in the same local transcript and never touches the proxy for that local copy. |
| Block risky prompts | `UserPromptSubmit` | A hook **cannot** rewrite a prompt, so a prompt carrying a secret (or a high-severity identifier like an RRN) is **blocked** with an actionable reason. Remove the value and resubmit. |
| Deny sensitive reads | `PreToolUse` (`Read`) | Denies reads of known credential/key files (`.env*`, `*.pem`, `*.key`, `id_rsa`/`id_ed25519`, `~/.aws/credentials`, …) before the file is opened — so their plaintext never reaches the transcript. Template files (`.env.example`) are allowed. |

All three call the same engine (`honmoon hook`), which reuses the exact Tier-1
detectors and tokenizer from `honmoon-core` — the crate that also backs the
proxy. On this client path the redaction is one-way (there is no reverse
substitution; the tokenizer's mapping is not shared with a proxy today). What
carries over is determinism: placeholders are byte-stable for a given secret
within a session, so re-redacting resent history keeps a provider's prompt cache
prefix intact.

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

Point Claude Code at this directory (`packages/claude-plugin/`) as a local
plugin (once the repo publishes a plugin marketplace, you'll be able to install
from there instead). See
[Claude Code plugins](https://code.claude.com/docs/en/plugins). Once installed,
`/hooks` should list the three honmoon hooks.

The manifest (`.claude-plugin/plugin.json`) deliberately has **no** `hooks`
key: Claude Code loads `hooks/hooks.json` automatically, and on 2.1.263 a
manifest entry pointing at that same file is reported as a duplicate and logged
as a hook-load failure (`manifest.hooks should only reference additional hook
files`). Do not add it back.

## Verify

```sh
# Redacts an Anthropic key in Read output → updatedToolOutput with a placeholder:
printf '{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":"API_KEY=sk-ant-api03-cache-stable-abcDEF123456"}' | honmoon hook

# Denies a Read of .env:
printf '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/proj/.env"}}' | honmoon hook

# Blocks a prompt carrying a secret:
printf '{"hook_event_name":"UserPromptSubmit","prompt":"deploy with sk-ant-api03-cache-stable-abcDEF123456"}' | honmoon hook
```

## Transcript hygiene — verified

`PostToolUse` `updatedToolOutput` is documented to replace what the **model**
sees; the docs do not spell out that the persisted transcript
(`~/.claude/projects/<project>/<session-id>.jsonl`) stores the redacted value.
That was verified empirically against **Claude Code 2.1.263** (2026-09-07,
issue #49): a headless session with this plugin loaded read a file carrying a
valid-checksum RRN and an Anthropic-shaped API key, and the session `.jsonl`
contained **zero** occurrences of either raw value. The placeholders appear in
every place the tool output is persisted — the `tool_result` block the model
sees, the `toolUseResult.file.content` field Claude Code keeps for `/resume`,
and the `hook_success` record that logs the hook's own stdout. A control run of
the same prompt without the plugin persisted both raw values, so the fixture
would have been transcribed without the hook.

Two things remain version-dependent, so re-run the check below when Claude Code
changes:

- Only the tool **output** is rewritten. The hook's stdin (the raw
  `tool_response`) is not persisted today, but that is an implementation detail
  of Claude Code, not a documented guarantee.
- For files that are *known* credential stores, the `PreToolUse` deny stays the
  guaranteed path: the file is never read, so there is nothing to rewrite.

To re-verify against your Claude Code version:

```sh
(
  set -e   # a failed step must never fall through to the cleanup below
  PROBE=$(mktemp -d /tmp/hm-probe-XXXXXX)
  cd "$PROBE" && git init -q
  printf 'rrn: 670125-1230644\nkey=sk-ant-api03-cache-stable-abcDEF123456\n' > notes.txt

  SESSION_ID=$(claude -p --plugin-dir /path/to/honmoon/packages/claude-plugin \
    --allowedTools Read --output-format json \
    'Read notes.txt and reply with its contents verbatim.' | jq -r .session_id)

  # The project directory is named after the *canonical* cwd, which is
  # platform-dependent (macOS resolves /tmp to /private/tmp), so find the
  # transcript by session id rather than by a hardcoded slug.
  set -- ~/.claude/projects/*/"$SESSION_ID".jsonl
  TRANSCRIPT=$1
  if [ ! -f "$TRANSCRIPT" ]; then
    echo "FAIL — no transcript found for session $SESSION_ID"
    exit 1
  fi

  # Assert a placeholder reached each of the three places the tool output is
  # persisted — counting occurrences would also be satisfied by three copies
  # in one of them — and that neither raw fixture survived anywhere.
  if jq -s -e '
          any(.[]; any(.message.content[]?;
                .type == "tool_result" and (.content | tostring | contains("<<hs:"))))
      and any(.[]; (.toolUseResult.file.content? // "") | contains("<<hs:"))
      and any(.[]; .attachment.type? == "hook_success"
                and ((.attachment.stdout? // "") | contains("<<hs:")))
        ' "$TRANSCRIPT" > /dev/null \
    && ! grep -q -e 670125-1230644 -e sk-ant-api03 "$TRANSCRIPT"
  then
    echo "PASS — every persisted copy was redacted"
    # Both paths belong to this probe alone. A control run without the plugin
    # stores the raw fixture, so clean that one up the same way.
    rm -rf -- "$PROBE" "${TRANSCRIPT%/*}"
  else
    echo "FAIL — keeping $PROBE and $TRANSCRIPT for inspection"
    exit 1
  fi
)
```

## Function hooks (early access)

Claude Code 2.1.263 ships a prototype **function hooks** API behind
`CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`: a plugin may name a TypeScript module in
`hooks/hooks.json` and register hooks that wrap the tool chain in-process. This
plugin ships one — `hooks/honmoon.ts` — beside the command hooks above. The API
is pre-release and may change between Claude Code releases.

```sh
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir /path/to/honmoon/packages/claude-plugin
```

Without the flag the module is ignored and only the command hooks run, so the
plugin works unchanged on older Claude Code versions.

### What changes versus the command hooks

| | Command hooks | Function-hooks module |
|---|---|---|
| Prompts | **Blocked** — a command hook cannot rewrite a prompt | **Rewritten**: the redacted prompt is submitted, with a context note telling the model values were replaced. It is dropped only when the engine is unreachable |
| Prompt PII floor | Severity **3** (high) — `handle_user_prompt_submit` | Severity **2** — the prompt is scanned as tool output, so medium-severity PII (email, phone) is rewritten too |
| Tool output | `Read`, `Bash`, `Grep` | `Read`, `Bash`, `Grep` **and `WebFetch`** |
| Engine unreachable | **Fails open** (the tool call proceeds unredacted) | **Fails closed**: the tool result is denied (`honmoon: redaction engine unavailable (…); tool output withheld`) and the prompt is dropped. Set `failMode: "open"` for the old behavior |
| Transport | `honmoon hook` subprocess | `honmoon hook` subprocess, or HTTP to the management API |

Only the `Read` result variants the detectors can read are rewritten: `text` and
`notebook` (its cells are plain JSON). An image or PDF record is base64 bytes and
is passed through untouched, as is a denied tool result. An errored result (a
non-zero Bash exit whose stderr holds a key, say) is scanned too: because a hook
cannot return its own `isError`, a redacted error goes back as a `deny` carrying
the redacted text, which the model reads as the tool's error.

### Options

Configure with `/plugin configure honmoon-redact`, or in settings.json under
`pluginConfigs["honmoon-redact"].options` (user, `--settings` or managed
settings — project settings are not read):

| Option | Default | Meaning |
|---|---|---|
| `transport` | `process` when `hookUrl` is unset | `process` runs `honmoon hook`; `http` POSTs the same JSON to `hookUrl` |
| `honmoonBin` | `honmoon` | The binary the `process` transport runs (command name or absolute path). Note this is a plugin option, not the command hooks' `HONMOON_BIN` env var — set both if honmoon is off `PATH` |
| `hookUrl` | — | Management-API endpoint, e.g. `http://127.0.0.1:7777/api/hooks/claude-code`. Setting it selects the `http` transport unless `transport` says otherwise |
| `hookToken` | — | Optional bearer token for `hookUrl` |
| `failMode` | `closed` | `closed` denies tool output / drops the prompt when the engine is unreachable; `open` passes through |

Each hook phase runs under its own 8 s budget, inside the host's 10 s
per-hook limit. The host budgets only the hook's own work, not the time the
tool spends inside `next()`, and the module mirrors that: the session lookups
and the `PreToolUse` check share one budget before the tool runs, and the
`PostToolUse` redaction gets a fresh one after it, so a slow tool never denies
its own redaction. Whatever is still pending when a budget runs out fails
closed instead of running past the host and being skipped. Every
failure path (spawn error, timeout, non-zero exit, unparseable stdout, HTTP
error, a rejected session lookup, a `transport` of `http` without a
`hookUrl`) is caught: the hook itself never throws.

### Both layers run at once

With the flag on, the command hooks **and** the module both fire on the same
tool call. This is harmless: placeholders are keyed by the session salt, so the
command hook redacts first (it runs beneath the module, inside its `next()`) and
the module then finds nothing left to redact and hands back the result it was
given, verbatim. Verified on 2.1.263 — the module's engine call returns an empty
verdict and the transcript carries one set of placeholders. Drop the `hooks` key
from `hooks/hooks.json` to run the module alone.

That holds for `transport: "http"` as well **when both transports derive from the
same machine key** — the per-machine random secret that keys the HMAC behind every
placeholder, read from `~/.honmoon/hook-salt` whenever that file is usable (see the
fallback note below for when it is not). What has to match is the key bytes; where they are stored
only matters in so far as it decides which bytes each process gets. Two processes
on one host reading one `$HOME/.honmoon/hook-salt` read the same bytes, which is
how the co-located deployment the `hookUrl` example above describes satisfies it.
Both transports then derive the salt from the payload's `session_id` under that
shared key, so one secret mints one `<<hs:…>>` token per session whichever layer
saw it: a `Bash` result redacted by the command hook and a `WebFetch` result
redacted by the module carry the identical placeholder (#98). A gateway started
with `--hook-salt-context` is the exception — that pins the endpoint to the given
context instead of the session, so either leave it unset or pin the command hooks
to the same value (`honmoon hook --salt-context`, or `HONMOON_HOOK_SALT_CONTEXT`
in their environment).

**Known limitation — different key bytes break parity.** Each process reads its own
`$HOME/.honmoon/hook-salt`, so anything that leaves those two reads holding
different bytes breaks the parity above. It happens on separate hosts; in a
container with its own filesystem, where an identical `HOME` path still names a
different file; under a different user; and for the same user whenever `HOME`
differs — a service unit with its own `Environment=HOME=`, or a `sudo` that resets
it. (A process with no `HOME` reads a `.honmoon` relative to its working
directory.) Those are examples of one condition, not a list to check off: different
key bytes, so the same `session_id` mints different placeholders. Matching
`--hook-salt-context` values do **not** close any of them — the context is mixed
into an HMAC the machine key keys, so mismatched keys stay mismatched.

**When the salt file is unusable, the key is not secret.** The loader only fails
when it has to mint a new salt and cannot — no readable `/dev/urandom`, or a
`~/.honmoon` it cannot create or write (read-only filesystem, unwritable `HOME`).
`honmoon hook` then prints `using fallback salt (…)` to stderr and keys the HMAC
with a constant compiled into the binary and published in this repository's source.
Placeholders on that path are still stable and still restore, but they are no longer
keyed by anything private: anyone can mint the placeholder a guessed secret would
produce in a given session and check it against a redacted transcript, so redaction
stops hiding which secrets a transcript contains. Note the direction — falling back
*improves* parity rather than breaking it, because two processes that both fail share
the same public constant and agree, so the parity above holds while the property it
is meant to protect is gone. Watch for that stderr line; #131 tracks whether failing
open is the right default here.

**Getting one key onto both sides.** Co-located processes sharing a `HOME` read one
file and need nothing. Anywhere else — separate hosts, containers, different users
— provision the *same* `hook-salt` to both: the loader adopts any existing file of
at least 16 bytes verbatim (re-tightening it to `0600`), so identical bytes at each
process's salt path mint identical placeholders. Cross-host parity is therefore
achievable; it is just not automatic.

Treat that as copying a secret, because it is. The machine key is what makes a
placeholder unforgeable, so everyone who holds it can mint the placeholder a given
session would produce for a guessed secret and check it against a redacted
transcript — the confirmation oracle tracked in #125. Move it only over a channel
you would use for any other credential, put it in as few places as the deployment
needs, and rotate it there if it leaks. It also rests on the salt loader's adoption
behaviour rather than on a supported setting; #126 tracks making the key an explicit
input. If none of that is worth it for your deployment, keep `transport: "process"`.

### Typings

`hooks/honmoon.ts` is typed against `.claude/types/claude-code.d.ts`, generated
by `/plugin-types` (its header records the Claude Code version that wrote it).
Regenerate after a Claude Code update:

```sh
cd packages/claude-plugin
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude -p --output-format text "/plugin-types"
```

`hooks/claude-code-grep.d.ts` adds `Grep`, which 2.1.263's `/plugin-types` does
not emit although the tool exists at run time; delete it if a regenerated
`claude-code.d.ts` declares `Grep` itself. `bun test` and `bun run typecheck`
cover the module.

## Known limitation — detector coverage

The detectors are **precision-first**, so a few shapes can slip through — the
proxy remains the wire-facing backstop, but for local transcript hygiene these
are gaps to be aware of:

- **Truncated PEM private keys.** A private-key block is only matched when both
  the `-----BEGIN … PRIVATE KEY-----` header *and* the matching `-----END …`
  footer are present (the footer anchor keeps prose that merely mentions a key
  from matching). Output that shows the header plus only part of the body — e.g.
  `head -5 id_rsa` via `Bash` — is not redacted. Prefer the `PreToolUse` deny
  for whole key files.
- **Generic-secret placeholder filtering.** The keyword-anchored
  `GENERIC_SECRET` detector drops values that look like placeholders by matching
  markers (`example`, `changeme`, `test`, …) as substrings, so a genuine
  high-entropy secret that happens to embed one of the short markers can be
  treated as a placeholder and passed through. Structural keys
  (`sk-ant-…`/`AKIA…`/`ghp_…`/…) are unaffected — they don't consult this list.

## Scope

The command hooks ship the **command transport** (works with only the binary
installed). A gateway-direct HTTP transport (`type: "http"` hooks posting to the
honmoon management API, sharing the tokenization mapping with a co-running proxy)
is a planned follow-up for them; settings-level HTTP hooks fail open, so it will
not become the silent default. The function-hooks module above already offers
the HTTP transport (`transport: "http"`), where honmoon controls the failure
mode itself and defaults to failing closed.
