---
name: pr186-warn-if-readable-beyond-owner
description: 'PR #186 (issue #173) token-file and token-directory mode checks — every hole found in mgmt_token.rs/auth.ts was FIXED there on BOTH sides (create_private_dir 0700, single-descriptor read, directory warn on every path); #188 (the session cookie) is itself now closed — the browser credential is an origin-scoped X-Honmoon-Session header, not a cookie. STILL OPEN in this domain: hook.rs salt dir has the same create_dir_all shape, no O_NOFOLLOW on either, and the #189 empty-token recovery race — report those against hook.rs/#189, not as new against mgmt_token.rs'
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
3. **FIXED in #186 — the description of this note said otherwise for one
   revision, so check the file, not a memory of it.** `packages/api/src/auth.ts`
   now warns on both the persisted-read path and the race-adopt path. It also
   reads the token and its mode through *one* descriptor (`readTokenAndMode`):
   a `readFileSync(path)` followed by a stat of `path` can land on two inodes if
   the file is replaced in between, which fails in the worst direction — the
   token adopted comes from the permissive file while the mode reported comes
   from the replacement, announcing a readable credential as safe. #188 was never
   about any of this — it was the session cookie, and that is closed too: the
   browser credential is now a session secret in the `X-Honmoon-Session` header,
   kept in origin-scoped `sessionStorage`, with no cookie to harvest.

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
