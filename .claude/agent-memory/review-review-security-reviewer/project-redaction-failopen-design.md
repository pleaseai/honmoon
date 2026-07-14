---
name: project-redaction-failopen-design
description: Honmoon's client-side redaction (Claude Code plugin / honmoon hook) is intentionally best-effort and fail-open; the proxy is the real enforcement backstop. Weight fail-open findings accordingly.
metadata:
  type: project
---

The `honmoon hook` command-transport backend and the `claude-plugin` redaction
hooks are deliberately **best-effort and fail-open**: on any error (unparseable
payload, unreadable/unwritable `~/.honmoon/hook-salt`, missing `honmoon` binary
in `redact.sh`) they degrade to a no-op and let content pass unredacted.

**Why:** Honmoon is a policy-based firewall gateway; the **proxy** covers the
wire (every secret re-crosses it each turn and is re-redacted). The plugin's job
is narrower — local **transcript hygiene** (keep plaintext out of
`~/.claude/projects/.../*.jsonl` before it's sent). The proxy remains the
enforcement backstop, so the plugin favors not-breaking-the-session over
hard-failing.

**How to apply:** When reviewing this redaction path, do NOT over-flag documented
fail-open behavior as critical — it's an accepted design tradeoff. DO still flag
gaps that defeat the plugin's *own* stated purpose (transcript hygiene) that the
proxy cannot cover — e.g. secrets read via the `Bash`/`Grep` tools (the hooks
only match the `Read` tool), which land in the local transcript and never touch
the proxy for that local copy. Those are real holes, not proxy-covered.
