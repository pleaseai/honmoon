---
name: pr186-warn-if-readable-beyond-owner
description: 'PR #186 (issue #173) mgmt_token.rs mode checks — four holes found in warn_if_readable_beyond_owner and the token directory; the three Rust ones were FIXED in that PR (including create_private_dir at 0700), only the missing packages/api/src/auth.ts warn equivalent is still open (tracked in #188)'
metadata:
  type: project
---

PR #186 added the management-token gate. Three coverage holes were found in
`crates/honmoon-cli/src/mgmt_token.rs`'s `warn_if_readable_beyond_owner`
(documented contract: "report — but do not correct — a token file the mode
leaves readable beyond its owner"). **Two were fixed in that same PR. Check the
file before citing any of this.**

1. **FIXED in #186.** The stat failure used to `return` silently, defeating the
   function's single documented purpose — silence there reads exactly like
   "checked, and it was fine". It now prints a warning naming the OS error.
2. **FIXED in #186.** It is now also called on the create-race adopt branch
   (`Err(e) if e.kind() == AlreadyExists`), which reaches the same
   `Source::Persisted` state as an ordinary read. Near-zero risk either way —
   the winner's file was created `create_new` + `mode(0o600)` microseconds
   earlier — but the asymmetry is gone.
3. **STILL OPEN, tracked as #188.** `packages/api/src/auth.ts`'s `resolveToken`
   has no equivalent check on its persisted-read path, so a file `chmod`'d wide
   open months after either process minted it is surfaced by the Rust operator
   and not the TS one. This is the instance that actually matters in practice.
   Report it against #188, not as new.

4. **FIXED in #186.** The *directory* was the gap the file-mode checks could not
   see. `create_dir_all` asks for `0777` and lets the umask subtract, so
   `~/.honmoon` came out `0755` — and `0775`/`0777` under a `002`/`0` umask,
   where any local user can unlink `mgmt-token` and substitute a `0600` file of
   their own. `warn_if_readable_beyond_owner` inspects that substitute, finds it
   well-moded, and stays quiet: the check looks at *read* bits on the file while
   the exposure is *write* permission on the directory. `create_private_dir` now
   asks for `0700` (a umask can only clear bits, so the result stays owner-only),
   and `warn_if_writable_beyond_owner` reports — does not tighten — an existing
   directory that is group/world writable. Pinned by
   `a_created_token_directory_is_owner_only`, verified red at `0755`.

   **Still open, and deliberately not in #186:** `crates/honmoon-cli/src/hook.rs`
   (`create_dir_all` at ~line 1093) has the identical shape for the salt
   directory, and no `O_NOFOLLOW`/symlink validation exists on either. Both were
   left out of scope; report them against that pair, not as new against
   `mgmt_token.rs`, which is fixed.

**Separately open: #189.** The empty-token recovery path (`existing.is_some()` →
truncating `write_secret_file`, and auth.ts's `'w'` open) is not single-winner,
so two concurrent starts can each return their own minted token. No lock-free fix
closes it — atomic publish leaves the divergence in memory, and publish-then-
re-read converges on only some interleavings — so it needs an `O_EXCL` sentinel
or an advisory lock in both languages. Do not re-report as new.

See [[project-hook-salt-audit-visibility-131]] for the related but distinct
audit-sink visibility pattern (`hook.rs`'s salt handling, which this module's
own doc comment explicitly contrasts itself against).
