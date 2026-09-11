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
is meant to protect is gone. Failing open here is deliberate — a hook that hard-fails
breaks the agent it runs inside — and #131 tracks whether that is the right default
for this key specifically.

**Make that degradation visible.** Do not rely on the stderr line: a hook runs
non-interactively, so it usually reaches nobody. Point the hooks at the audit log
instead, by exporting `HONMOON_AUDIT_LOG` in the agent's environment (the plugin's
dispatcher runs `honmoon hook` with no arguments, so the flag form
`honmoon hook --audit-log <file>` is only useful when invoking it by hand):

```sh
export HONMOON_AUDIT_LOG=honmoon-audit.jsonl   # the file `honmoon gateway --audit-log` writes
```

Each degraded derivation then appends one `"decision":"degraded"` event naming the
transport and what the loader observed. Only degradations are written from the hook,
never per-invocation verdicts, so a healthy host leaves the file untouched: an event
appearing there at all is the signal.

Two independent things can be wrong with the key, so `rule` says which one this event
is about:

| `rule` | What went wrong |
| --- | --- |
| `hook-salt-fallback` | the key in use is **not** the persisted one; `key_source` says what that cost |
| `hook-salt-exposed` | the key **is** the persisted one, but its file is readable by other local users and the loader could not restrict it to `0600` |

On the fallback rule, `key_source` says which guarantee was lost, because they are not
the same failure:

| `key_source` | Key | What is lost |
| --- | --- | --- |
| `persisted` | the random secret at `~/.honmoon/hook-salt` | nothing about the key's provenance — this value appears only under `hook-salt-exposed` |
| `unpersisted` | random and private, but never reached disk | byte-stable placeholders across turns and transports (#20, #98). Still unforgeable |
| `fallback` | the constant compiled into the binary | unforgeability, entirely — the key is published in this repository |

**A salt anyone can read is a published key.** `~/.honmoon/hook-salt` is created `0600`,
and the loader re-tightens it on every read in case a backup restore or an older build
left it looser. Where that `chmod` cannot be applied — a root-owned `0644` file, a
read-only mount — the salt is adopted anyway, because refusing to redact is worse; any
local user who can read it can then mint the placeholder a guessed secret would produce
in a given session and check it against a redacted transcript, exactly as under a
`fallback` key. `hook-salt-exposed` is what makes that visible, and its `reason` names
the mode observed:

```
salt file /home/a/.honmoon/hook-salt is readable beyond its owner (mode 0644) and could not be restricted to 0600
```

Note what that event does and does not attest. It is raised on the **mode read back
after** the attempt, not on the `chmod` returning an error — a read-only mount fails the
call on a file that is already `0600`, and a degraded event there would be a false alarm
about a correctly-permissioned key. By the same token, its *absence* means the file was
owner-only when the loader looked, not that it was never readable by anyone else: a
`chmod` that succeeds closes the window going forward and says nothing about the one
before it. Nor does it reach past the POSIX mode bits: on macOS an ACL entry
granting another local user read leaves the mode at `0600`, and this check cannot
see it.

**So honmoon reports currently-observable exposure only, and cannot attest history.**
A clean log is not a clean bill of health for this key. The loader learns a mode at
the instant it looks, never how long the file carried it — a `0600` salt today may
have been `0644` last week, and no number of stats would tell you. That limit is
worth knowing because the two cases need *different* responses: for a key that is
exposed **now**, tightening the mode is the fix, which is what the loader already
tries; for a key that **was** exposed, tightening it is not, because the bytes are
already out and only regenerating the salt helps. honmoon raises no event for the
second case today ([#143](https://github.com/pleaseai/honmoon/issues/143) tracks
whether it should), so if you have reason to think the file was ever readable by
another local user — a restored backup, a shared home, a permissive umask — rotate
on that suspicion rather than waiting for a signal that will not come.

To rotate: delete `~/.honmoon/hook-salt` once its permissions can be fixed and let the
next invocation mint a new one. Placeholders for the same secret change at that point,
so an in-flight session's transcript stops matching earlier turns — losing the
byte-stability #20 and #98 are about. Rotate between sessions where you can.

**Where each event is visible.** The two transports reach different readers, because
the gateway's management API (`/api/audit`, which the embedded dashboard polls) serves
its own in-process ring rather than the file:

| Recorded by | In the JSONL file | `@honmoon/api` (`GET /api/audit?decision=degraded`) | Gateway dashboard |
| --- | --- | --- | --- |
| `honmoon hook` (its own process, per invocation) | yes | yes | **no** |
| `honmoon gateway` (once at startup, covering the HTTP transport and wire redaction) | yes, when `--audit-log` is set | yes | yes — a `Degraded` pill |

That table holds for both rules: each process records what its own key read observed, so
an unrestrictable salt reaches the same surfaces a fallback key does.

So a hook-side degradation is found by querying the log, not by watching the dashboard.

In practice the condition still reaches the dashboard on any host that runs a gateway,
because the trigger is shared: both processes read the same `~/.honmoon/hook-salt`, so
whatever makes it unusable for the hook makes it unusable for the gateway, which then
records its own event into the ring the dashboard polls. What the dashboard cannot show
is the hook's *own* records — the per-invocation cardinality, and the hook-specific
reason. A host running no gateway has the log and the query API only.

Pointing both processes at one file is intended: each appends whole lines, and the query
layer orders by timestamp because ids are process-local.

**Pick a path on a different filesystem from `~/.honmoon` where you can.** The
conditions that make the salt unwritable — a read-only filesystem, a full disk, an
unwritable `HOME` — can equally stop the audit log from being opened or appended to.
`honmoon hook` reports that on stderr and carries on (reporting a degradation must
never become one), but stderr is the channel this setting exists to stop relying on,
so a correlated failure leaves the degradation unrecorded.

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
