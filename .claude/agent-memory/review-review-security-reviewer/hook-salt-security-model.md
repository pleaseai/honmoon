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
- Salt file + any temp should be mode `0600`. Newly created files are `0600` from the
  open mode; the *recovery/overwrite* path (`write_secret_file` on a pre-existing
  short/corrupt `hook-salt` that some external actor left group/world-readable) writes
  the bytes before its trailing `set_permissions_0600`, so there is a brief transient
  window where a pre-existing looser file holds new bytes at its old mode. Freshly
  created temps/targets have no such window.
- The `.honmoon` dir is created via `create_dir_all` at umask default (~0755) and is
  owned by the user — so the 0600 file contents are safe from other UIDs *as long as
  the dir is not attacker-writable*. An attacker-writable salt directory (group-writable
  or world-writable — the relative `.honmoon` fallback when `HOME` is unset, or a
  misconfigured `$HOME`) breaks that assumption.
- Fail-open fallback key `b"honmoon-hook-v1-fallback-key"` is **by design** (documented
  tradeoff) — do NOT flag it as a vuln.

**How to apply:** when reviewing this file, focus on filesystem-safety of the
create/link/read sequence (symlink follow, TOCTOU, predictable temp names) rather than
the fallback key. The 2026-07 hard_link rewrite publishes the first-run salt by writing
it to an **exclusively-created** temp (`O_CREAT|O_EXCL`, mode 0600) at an unguessable
**random** name, then `hard_link`ing it onto `hook-salt`. The random + exclusive temp
blocks *pre-planting* (an attacker cannot create a symlink/file at a path they cannot
guess), but this is **not** full symlink-safety: in an attacker-writable, *observable*
dir an attacker can still replace the temp between its close and the `hard_link`
(TOCTOU), and the top-level and lost-race `std::fs::read(hook-salt)` follow a symlink —
so a planted target could substitute the adopted HMAC key. All of this is reachable only
in an **attacker-writable salt-directory** (including group-writable/shared paths — the
attack needs write access, not specifically *world*-writable; the `HOME`-unset relative
fallback is unsafe only when its CWD is attacker-writable); the default user-owned
`$HOME/.honmoon` is safe as long as it is not attacker-writable.
To fully close it for hostile-directory deployments, use fd-based linking (`O_TMPFILE` +
`linkat`) and `O_NOFOLLOW`/`symlink_metadata` on the reads.
