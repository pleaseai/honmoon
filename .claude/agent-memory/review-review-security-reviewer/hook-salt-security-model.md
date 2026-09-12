---
name: hook-salt-security-model
description: "honmoon-cli hook machine-salt security model — 0600 invariant, HMAC-SHA256 unforgeability key, fail-open fallback; recurring security-review target; `reason` content settled as deliberate (#162), the unauthenticated mgmt reads are #173, the replaced-unread fourth rule shipped in #171 with its three review gaps closed in the same PR"
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
paths and OS errors, surfaced by the unauthenticated `GET /api/audit` and the dashboard
— **that content is settled, see the #162 entry below.** No key bytes are serialized —
`MachineKey`/`MachineKeySource` derive no `Debug`.

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

**2026-09 (#162) — the path and OS error in `reason` are deliberate, and now absolute.**
The question was whether to trim `reason` to an error kind because `GET /api/audit` is
unauthenticated. Settled: no. `reason` is the hook transport's only durable channel
(fresh process, no ring, `tracing` filtered without `RUST_LOG` — #131), and the same
unauthenticated response already serves every domain contacted, request path, SQL table
and PII category, so trimming one field costs diagnostics while leaving strictly more
sensitive fields in the same body. The trim is also near-reversible: the rule name plus
a salt location documented in the plugin README reconstructs everything but the home
directory. `load_or_create_machine_salt` now resolves `dir` through `absolute_salt_dir`
(lexical `std::path::absolute`, not `canonicalize`), so the `HOME`-less relative
`.honmoon/hook-salt` no longer reaches the log as a path nothing can resolve.

**The missing auth layer on the management reads is the real exposure and is tracked
as #173** — `/api/audit`, `/api/approvals` and `/api/policy` all skip the `authorized()`
helper that `POST /api/hooks/claude-code` calls. When reviewing this area, raise 173
rather than the salt path and OS error.

**Scope of that settlement, exactly: two payloads — a local salt path, and an OS error.
Not the field.** Three things it does NOT cover, all still reportable:
- A *future* producer putting something else in this `String`. Nothing has reviewed that.
- The working-directory axis the absolutization itself introduces. `$HOME` is recoverable
  from `passwd`, so naming it discloses little to a local reader; a `HOME`-less gateway
  (a systemd unit with no `Environment=HOME`, a container entrypoint, `env -i`) now has
  its **cwd** filled in instead, and nothing else in the response reveals that. Accepted
  in #162 as the price of a followable path, and argued there — but it is a disclosure
  delta, not the neutral change the first draft of that PR called it.
- A resolution that failed: `absolute_salt_dir` falls back to the path as given and says
  so on stderr only, so the record cannot distinguish "tried and could not read the cwd"
  from "never tried". Tracked as **#176** — report it against that, not as new.

**2026-09 (#171) — the replaced-unread arm has a fourth rule.** The failed-read overwrite
arm (`read` fails non-`NotFound`) records `hook-salt-replaced-unread`: a `reason` naming
the discarded file's mode as stat'd before the overwrite, and **no exposure claim** — the
contents were never seen. `degradations()` returns up to two records (key-in-use +
replaced-unread) and both sinks loop over them, so neither suppresses the other. As merged,
verified once — do not re-derive:
- **`key_source` on this rule is not a constant.** It names the key *in use*:
  `persisted` where the replacement landed, `fallback` where the loader destroyed the file
  and then could not write one. `degradations()` reads it off `status.source` via
  `key_source_of`. A finding that it "should be persisted" is wrong.
- The record is owed from `write_secret_file`'s **truncating open** onward, which
  `SecretWriteError::truncated` carries: a failure at the open destroyed nothing and owes
  nothing; a failure after it owes the record even though no replacement landed. Do not
  re-report the truncate-before-write gap — that was the review finding on this PR and it
  is fixed.
- `record_machine_key_status` attempts every owed record and returns one `Err` naming
  **every** rule the sink refused; `audit_machine_key_status` opens the sink once and emits
  one self-contained response line per refused record. No record is lost on partial sink
  failure.
- The `reason` adds no payload class beyond the #162 settlement (path + OS error + a mode
  the exposure reasons already carry).
- Suppression/forgery by a local attacker needs an attacker-writable `~/.honmoon`; a
  non-owner cannot `chmod` to mislead the pre-overwrite stat.

**The wording is deliberately non-simultaneous.** The `reason` says the mode was seen
"when the loader last looked, just before discarding it", never "when the loader replaced
it" — the stat runs several syscalls earlier, path-based and symlink-following, so a
concurrent loader can intervene. That is the #172 class; report it there, not as a new
finding here.

**This rule does not always fire once, and that is documented.** On a salt owned by
another uid that this user can write but not read, the `chmod` cannot take, the
replacement stays unreadable, and every invocation replaces again — raising this rule
beside `hook-salt-exposed` and rotating the machine key each time, so placeholders stop
being byte-stable (#20, #98). The README says so, including that such a host always
rotated every invocation and the rule merely makes it visible. Likewise the overlap
window: it is **wider** than `hook-salt-was-exposed`'s, not narrower, and nothing locks
the file — also stated. Do not re-raise any of the three as new.

**#172** carries the older path-based-observation entry above: read/chmod/stat still
resolve `path` separately, so the mode observed is not bound to the inode the bytes came
from.

**2026-09 (#165) — a refused sink now escalates to the hook response.**
`audit_machine_key_status` returns `Option<String>`; `run` puts it on the verdict as the
Claude Code `systemMessage` common field via `attach_system_message`. Verified once, do not
re-derive: the plugin registers only `PreToolUse` / `PostToolUse` / `UserPromptSubmit`
(`packages/claude-plugin/hooks/hooks.json`), all synchronous (`async` is not set), and on those
events `systemMessage` is shown to the user and **not** added to the model's context — so the
"never feeds the transcript" claim in the doc comments holds. It would *not* hold for an
`async: true` command hook, where Claude Code delivers `systemMessage` to Claude on the next
turn; re-check that config if the hook ever goes async.
The message body is `rule` / `key_source` / `reason` / `sink` / `sink_error`. `rule` and
`key_source` are static, `reason` is the #162-settled payload, and `sink` is operator config —
no attacker-controlled bytes reach it, so terminal-escape or JSON injection into the response is
not a live shape here (serde_json escapes it besides). The one delta worth remembering: this is
a **new channel** for the settled payload, and in headless runs (`--output-format stream-json`)
`systemMessage` surfaces as an `SDKInformationalMessage`, so a `$HOME`/cwd path and an OS error
can land in CI logs that may be more widely readable than the local JSONL.
`degradations()` is the shared classifier behind both channels (it was `degradation()`,
returning at most one, until #171 made a derivation able to owe two). It is **no longer**
equivalent to the removed `is_degraded()` gate: that gate was silent for the pair
`(Persisted, None)`, and `degradations()` returns empty only for the *triple*
`(Persisted, None, replaced_unread: None)` — a derivation that landed its replacement over an
unread file is `(Persisted, None, Some(..))`, healthy on both old axes and still owed a record.
`key_in_use_degradation()` is the half that kept the old equivalence.
