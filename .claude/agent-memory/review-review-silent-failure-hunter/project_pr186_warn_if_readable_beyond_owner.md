---
name: pr186-warn-if-readable-beyond-owner
description: 'PR #186 (issue #173) mgmt_token.rs warn_if_readable_beyond_owner — three coverage holes found; the two Rust ones were FIXED in that PR, only the missing packages/api/src/auth.ts equivalent is still open (tracked in #188)'
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

See [[project-hook-salt-audit-visibility-131]] for the related but distinct
audit-sink visibility pattern (`hook.rs`'s salt handling, which this module's
own doc comment explicitly contrasts itself against).
