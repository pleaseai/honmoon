---
name: hook-salt-security-model
description: honmoon-cli hook machine-salt security model — 0600 invariant, HMAC-SHA256 unforgeability key, fail-open fallback; recurring security-review target
metadata:
  type: project
---

`crates/honmoon-cli/src/hook.rs` persists a first-run machine salt at
`$HOME/.honmoon/hook-salt` (relative `.honmoon` if `HOME` is unset).

**Why it matters:** the salt is the HMAC-SHA256 key behind placeholder
*unforgeability* (`session_salt`). If an attacker learns/controls the salt they can
forge placeholders. Redaction still works without it (fail-open).

**Security invariants to check on any change here:**
- Salt file + any temp must be mode `0600` at all times, no looser transient window.
  `write_secret_file` opens O_CREAT mode 0600 AND calls `set_permissions_0600` after.
- The `.honmoon` dir is created via `create_dir_all` at umask default (~0755) and is
  owned by the user — so the 0600 file contents are safe from other UIDs *as long as
  the dir is not attacker-writable*. The relative `.honmoon` fallback (HOME unset) can
  land in a world-writable CWD, which breaks that assumption.
- Fail-open fallback key `b"honmoon-hook-v1-fallback-key"` is **by design** (documented
  tradeoff) — do NOT flag it as a vuln.

**How to apply:** when reviewing this file, focus on filesystem-safety of the
create/link/read sequence (symlink follow, TOCTOU, predictable temp names) rather than
the fallback key. The 2026-07 hard_link rewrite publishes the first-run salt by writing
it to an **exclusively-created** temp (`O_CREAT|O_EXCL`, mode 0600) at an unguessable
**random** name, then `hard_link`ing it onto `hook-salt` — so the temp write is
symlink-safe (cannot follow or clobber a pre-planted path) and the publish is atomic.
Still open (pre-existing, not introduced by the rewrite): the top-level and lost-race
`std::fs::read(hook-salt)` follow a symlink, so a planted `hook-salt` symlink in an
attacker-writable dir could substitute the adopted HMAC key — only reachable in the
non-default world-writable `.honmoon` case (relative fallback when `HOME` is unset).
Harden with `O_NOFOLLOW`/`symlink_metadata` if that deployment matters.
