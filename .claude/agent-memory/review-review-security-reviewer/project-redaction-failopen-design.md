---
name: project-redaction-failopen-design
description: Honmoon's client-side redaction (Claude Code plugin / honmoon hook) is intentionally best-effort and fail-open; the proxy is the real enforcement backstop. Weight fail-open findings accordingly.
metadata:
  type: project
---

The `honmoon hook` command-transport backend and the `claude-plugin` redaction
hooks are deliberately **best-effort and fail-open**: an unparseable payload or a
missing `honmoon` binary in `redact.sh` degrades to a no-op and lets content pass
unredacted. A salt-file I/O error (`~/.honmoon/hook-salt` unreadable/unwritable)
is **not** a no-op — it falls back to a fixed key and still redacts, relaxing only
placeholder unforgeability (not the redaction itself).

**Why:** Honmoon is a policy-based firewall gateway; the **proxy** covers the
wire (every secret re-crosses it each turn and is re-redacted). The plugin's job
is narrower — local **transcript hygiene** (keep plaintext out of
`~/.claude/projects/.../*.jsonl` before it's sent). The proxy remains the
enforcement backstop, so the plugin favors not-breaking-the-session over
hard-failing.

**How to apply:** When reviewing this redaction path, do NOT over-flag documented
fail-open behavior as critical — it's an accepted design tradeoff. DO still flag
gaps that defeat the plugin's *own* stated purpose (transcript hygiene) that the
proxy cannot cover. The sharpest residual gap: `Bash`/`Grep` output is redacted in
the **model context** (`PostToolUse` matches `Read|Bash|Grep`), but **pre-execution
blocking is `Read`-only** and `updatedToolOutput` is not guaranteed to scrub the
persisted `.jsonl`, so a `cat .env` can still leave plaintext in the local
transcript. That transcript copy never touches the proxy — a real hole, not
proxy-covered.
