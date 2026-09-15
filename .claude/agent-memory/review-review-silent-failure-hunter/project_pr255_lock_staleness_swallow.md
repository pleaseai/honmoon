---
name: pr255-lock-staleness-swallow
description: 'PR #255 (issue #189) mgmt-token lock — the staleness check swallowed every stat error as "not abandoned" with no logging, against this same file''s own warn_if_writable_beyond_owner convention; fixed before merge, and the convention is the durable part'
metadata:
  type: project
---

PR #255 added an `O_EXCL` sentinel (`mgmt-token.lock`) so both
`crates/honmoon-cli/src/mgmt_token.rs` and `packages/api/src/auth.ts` mint the
management token single-winner. **Both gaps below were fixed before merge** — recorded
for the convention they establish, not as open findings.

**The gap.** `lock_is_abandoned` (`std::fs::metadata` then `.modified()`) and
`lockIsAbandoned` (`statSync`) swallowed *every* error from the stat call — not only
the lock having been removed concurrently, which was the one case their doc comments
reasoned about — and returned "not abandoned" with no logging. A persistent
`EACCES`/`EIO` was then indistinguishable from a live holder: the waiter polled until
the 30s budget elapsed and bailed with "delete the lock if no other honmoon is
running," which is actionable-looking and wrong, because the real cause was never a
competing process. The "stated sub-guarantee narrower than the implementation's actual
swallow" shape from [[framing-deliberate-skips]].

**The convention it violated, which is the reusable part.** `warn_if_writable_beyond_owner`
in the same file has always warned and returned on the same kind of `metadata()`
failure rather than treating it as fine. This module's rule is that a check which
could not run must never read as a check that passed. The merged code follows it:
`NotFound` returns `false` silently (the protocol working), every other stat error
warns with the OS error first.

**Secondary, also fixed.** The waiter's `continue` after `break_abandoned_lock` skipped
the poll-interval sleep, so a rename that permanently failed tight-looped stat + rename
+ warn until the budget elapsed. `break_abandoned_lock` now returns whether it made
progress and the waiter sleeps when it did not.

Checked clean and still clean at merge: `read_on_disk`/`readOnDisk` mapping
`NotFound`/`ENOENT` to `Absent` at all three call sites; the loop cannot report success
without a publish nor failure after one; `break_abandoned_lock`'s
NotFound-as-"another waiter won" per its rename-is-a-claim design.

One caution for a later round: the staleness check now uses `symlink_metadata`/`lstatSync`
deliberately, and a non-regular lock path is treated as breakable on purpose — see
[[mgmt-token-lock-protocol]] before reporting either as a bug.
