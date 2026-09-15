---
name: mgmt-token-lock-warn-seams
description: 'packages/api/src/auth.ts lock branches that look like they need two processes are testable in one, because console.warn fires at three known points inside resolveToken — which seam reaches which branch, including the in-lock adopt branch the directory-mode seam reaches by publishing rather than corrupting'
metadata:
  type: project
---

`resolveToken`'s lock protocol reads like it needs concurrent interpreters to test: the
branches are about another start breaking, taking or publishing under this one's lock.
Most of them do not. `console.warn` is called at points the test can stub, and a stub
that mutates the filesystem *inside* the warning puts the process in the state a rival
would have produced — deterministically, in one process, with no timing.

The seams, in the order `resolveToken` reaches them (PR #262 / issue #256):

1. **`warnIfDirectoryWritableBeyondOwner(dir)`**, matched on `writable beyond its owner`.
   Fires after the pre-lock `readOnDisk` and before `acquireLock` — which is the whole
   window a rival has between this start's two reads, so it reaches two branches
   depending on what the stub leaves behind. Needs `chmodSync(dir, 0o777)` to arm, and
   no token file — a token returns before the lock is taken.
   - **Corrupt** the token file here and the *re-read under the lock* is the first read
     that can fail: `releases the lock when the re-read under it fails`.
   - **Publish** a valid token here (rename, `0600`) and this start still wins the `wx`
     race but finds a token under its own lock: `adopts a token published under the lock
     it won, and publishes nothing of its own` — the in-lock adopt branch (issue #265).
     Leave no lock file, since the rival released before this start acquired.
2. **The empty-file warning**, matched on `is empty`. Fires under the lock and before the
   identity check, so swapping the lock file for a different inode here is exactly what a
   break leaves behind. That is `leaves a successor's lock alone when its own was broken, and adopts its token`.
   Use `rmSync` then `writeFileSync`, not a write in place: the identity check compares
   inodes and only a new file gives it something to see.
3. **The abandoned-lock warning**, matched on `treating it as abandoned`, which the
   existing break test asserts on rather than uses as a seam.

**Distinguishing the two reads is the assertion that matters.** A test whose setup makes
the *pre-lock* read fail never creates a lock, and then `expect(existsSync(lock)).toBe(false)`
passes on a lock that never existed rather than on one that was released — the vacuous shape
PR #255 had to restructure two tests for (see
[[pr255-mgmt-token-lock-claims]] item 6). Pin it: assert the stub actually fired, and choose
a corruption whose error the pre-lock read could not have produced.

**The seam does not have to be on the branch.** The in-lock adopt branch (`case 'token'` in
`attemptUnderLock`) has no side effect of its own to hook, which is why issue #265 proposed a
test-only export or `mock.module` on `openSync`. Neither was needed: a branch is reachable
from any seam that can establish its *precondition*, and seam 1 above runs in exactly the
window that one needs. Check the window before concluding a branch needs a new surface —
especially on this module, where the surface would be a credential's.

**Assert what was not written, not only what was returned.** `source: 'persisted'` with the
rival's token also passes for a start that adopts *and* republishes, which still hands the
gateway a file it no longer wrote. Pin it with the token file's bytes *and* its inode:
`publishToken` renames, so any publish by this start replaces the rival's inode even when the
bytes would match. All three regressions — adopt→mint, adopt-then-write-the-mint, and a
byte-identical republish — fail on a different assertion, which is what says none of them is
carrying the others.

**Check every release path against the guard, not the prose.** Downgrading
`using held = acquireLock(...)` to `const held = ...` should turn every release test red; if
one stays green it is asserting something other than the release.
