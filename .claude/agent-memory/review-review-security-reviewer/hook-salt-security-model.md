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

**2026-09 (#98) — derivation is now shared and per-session.** `derive_hook_salt` /
`hook_salt_context` live in `crates/honmoon-core/src/hook_salt.rs`; `honmoon-mgmt`
exposes `pub enum HookSalt { Fixed{salt}, PerSession{machine_key} }` on `AppState`
and derives per request from the **request body's** `session_id`. Two consequences to
re-check on any future change here:
- The mgmt process now retains the **master machine key** (not a derived, scoped salt)
  for its lifetime, reachable through the public `AppState.hook_salt` variant field.
- `POST /api/hooks/claude-code` (unauthenticated unless `--hook-token`) is a
  placeholder-minting oracle under a **caller-chosen session salt** — guess-confirmation
  against another session's placeholders is now possible where it was not before.
- Empty-key guards moved into `HookSalt::fixed`/`per_session`; `hook::machine_key()`
  never returns empty (>=16B file, 32B fresh, or the fallback constant), so the asserts
  are startup-only, not a remote panic.

**2026-09 (#131) — fallback is now reported to the audit log.** `machine_key()` returns
`MachineKey { bytes, source }`; a `Fallback { reason }` source makes `honmoon hook` open
an operator-supplied JSONL path (`--audit-log` / `HONMOON_AUDIT_LOG`) via
`AuditLog::with_file` and append a `Decision::Degraded` event carrying
`RedactionFacts { key_source, transport, reason }`. Re-check on changes here: the sink is
now **multi-process** (hook subprocess + gateway append to one file, `write_all` of one
buffer on `O_APPEND` — not a hard atomicity guarantee on NFS/short writes); the path is
opened with `create(true).append(true)`, so it follows symlinks and blocks on a FIFO in a
process contracted to exit fast; and `reason` is an `anyhow` chain that embeds `$HOME`
paths and OS errors, surfaced by the unauthenticated `GET /api/audit` and the dashboard.
No key bytes are serialized — `MachineKey`/`MachineKeySource` derive no `Debug`.

**2026-09 (#141) — exposure is a second axis on the key status.** `MachineKeySource`
(provenance) is now wrapped in `MachineKeyStatus { source, exposure }`;
`restrict_to_owner_only(path)` chmods 0600 then re-`metadata`s and returns
`Some(reason)` when `mode & 0o077 != 0`, which becomes a `Decision::Degraded`
event with `rule: "hook-salt-exposed"` and `key_source: persisted`. What the
predicate deliberately does NOT cover, and is worth re-checking on any change:
- a **successful** chmod reports `None` — a salt that was 0644 until the loader
  repaired it raises no event, so an already-copied key is never rotated;
- **ownership** is never checked (no `MetadataExt::uid()`), so an adopted salt
  owned by another uid at 0600 is reported healthy;
- macOS NFSv4 ACLs survive `chmod` and are invisible to the mode-bit test;
- read (T0) → chmod → metadata (T1) is path-based and symlink-following, so the
  observed mode need not be the mode of the bytes adopted (attacker-writable dir
  only — outside the documented threat model).

**2026-09 (#143) — exposure is now two variants, read around the chmod.**
`restrict_to_owner_only(path, SaltProvenance)` does `stat` (FromFile only) → `chmod`
→ `stat`, returning `Option<SaltExposure>`: `Open` = still loose after the attempt,
rule `hook-salt-exposed`; `Closed` = found loose and **not** seen loose afterwards,
new rule `hook-salt-was-exposed`. `SaltProvenance::FreshlyWritten` (the
`write_secret_file` truncate path) deliberately skips the pre-`stat`, so the mode of
the inode a fresh secret is written into is never read as that key's history.

Two of the three gaps found on PR #170 were **fixed in that PR** — recorded because
the shapes recur, not as open findings:

- A failing post-correction `stat` used to `return None`, discarding an
  already-confirmed loose `found`. `found_exposure` now reports it, with a `reason`
  that names the mode seen and omits the "is now mode NNNN" clause it cannot fill.
  The general shape: **positive evidence downgraded to silence because a second,
  unrelated observation failed.** Worth grepping for on any `Option` early return
  that sits downstream of a successful observation.
- The shared doc comments claimed `None` attests "owner-only at the two instants the
  loader looked"; `FreshlyWritten` looks once and `publish_secret_atomically`'s
  winner path looks zero times. Both docs now scope the count to the provenance.

Still open, tracked as **#171**: the `must_overwrite` arm is also reached when `read`
fails with a non-`NotFound` error, where the discarded file may have held a valid salt
other processes adopted. The key being written is correctly unexposed; the *replaced*
key's exposure is what goes unrecorded, and routing it through this channel would pair
a history claim with a `key_source` describing a different key — which is why it was
split out rather than folded in. **#172** carries the older path-based-observation
entry above: read/chmod/stat still resolve `path` separately, so the mode observed is
not bound to the inode the bytes came from.
