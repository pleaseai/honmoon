---
name: project-hook-salt-was-exposed-143
description: PR #170 (issue #143, hook-salt-was-exposed rule) — my pass called the logic clean and it was not; two other reviewers found a discarded exposure I had walked past
metadata:
  type: project
---

PR #170 adds `SaltExposure::{Open,Closed}` and `SaltProvenance::{FromFile,FreshlyWritten}`
to `crates/honmoon-cli/src/hook.rs`, reporting a new `hook-salt-was-exposed` rule when the
loader finds the persisted salt file loose and successfully tightens it (previously silent).
Builds on [[project_hook_salt_fallback_visibility_131]] and [[project_hook_salt_parity_98]].

**What my pass got wrong, and it is the useful part of this note.** I traced
`restrict_to_owner_only`'s pre/post-chmod logic and reported it correct, naming the
`found?` early return as evidence the function "never claims backwards". I checked the
arm where the *pre*-chmod stat is unreadable and stopped there. The security reviewer and
the silent-failure hunter both found the other direction on the same read: when the
*post*-chmod stat failed, the function returned `None` and threw away a mode it had
already successfully observed as loose — a confirmed exposure of the key in use,
discarded because a second, unrelated observation could not be made. Fixed in-PR
(`found_exposure` now reports what was seen, with a `reason` that does not claim a mode it
could not read).

The lesson generalises past this file: a function with two symmetric observations has two
failure directions, and verifying one of them reads exactly like verifying the function.
Enumerate the pairs before declaring a control-flow review clean. Same shape as
[[project_audit_sink_nofollow_138]]'s FIFO test, which proved one refusal path and looked
like it proved both.

Current state after the fix, verified against the merged head:

- `Open` wins whenever the post-chmod mode is still loose, regardless of the pre-chmod
  mode; `Closed` when the pre-chmod mode was loose and the post-chmod one was not
  observed loose — including the arm where it could not be read at all, whose `reason`
  omits the "is now mode NNNN" clause rather than inventing one.
- `write_secret_file`'s `FreshlyWritten` waiver holds structurally: `found` is forced to
  `None` before the `Closed`-producing branch, so that path cannot return `Closed`.
  Verified by reading the code. **But the waiver's scope is narrower than it looks** —
  `write_secret_file`'s single caller (`load_or_create_machine_salt`'s `must_overwrite`
  branch) is reached from two arms, and on the `Err(e) if e.kind() != NotFound` arm the
  discarded bytes were never read, so they may have been a salt other invocations
  adopted. The *new* key is correctly unexposed either way; the *replaced* key's exposure
  goes unrecorded, which is #171.
- No call path produces `Closed` for a key that is not the bytes in use.

The `packages/policy/src/index.ts` miscount I found ("all three of those rules" where only
the two exposure rules carry `key_source: persisted`) was real and is fixed in-PR. Three
reviewers reported it independently, which says the enumeration-count check is cheap and
worth running first on any TD-001 mirror edit.
