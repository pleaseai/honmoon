---
name: mgmt-token-lock-protocol
description: 'The mgmt-token single-winner protocol as merged in PR #255 (issue #189) — an O_EXCL sentinel plus a rename-based publish, in crates/honmoon-cli/src/mgmt_token.rs and packages/api/src/auth.ts — what it defends against, which residual is documented by design, and the symlink semantics verified empirically so they are not re-derived'
metadata:
  type: project
---

The state **as merged**. Earlier revisions of this note described the mid-review
code and are superseded; re-verify line anchors before citing.

**Shape.** `mgmt-token.lock` beside `mgmt-token` in `~/.honmoon` (`0700`). Taken with
`O_CREAT|O_EXCL` at `0600` (`acquire_lock` / `acquireLock`). It holds the holder's pid as a
*diagnostic only* — staleness is mtime-based and the pid feeds no decision, so a "pid is not
a liveness check" finding is already answered in the doc comment. A waiter polls every 20ms,
adopts whatever the winner publishes and **never mints**; a 30s budget then refuses, again
without minting; a lock older than 10s is broken by `rename` to
`mgmt-token.lock.abandoned.<pid>` and unlinked (rename-as-claim, so simultaneous breakers do
not each delete a successor's fresh lock).

**The lock is half the mechanism; the publish is the other half.** Publishing is
write-to-`mgmt-token.new.<pid>`-then-`rename` on both sides. This is not decoration and a
proposal to write in place should be refused: the lock does not keep waiters out of the
token file — they poll it by design — so an in-place write is visible to them half-finished
and a waiter adopts the prefix. That is observed, not theoretical; the PR's own race test
caught a start holding a 63-character token against a 64-character file. The lock makes
exactly one start *decide* to mint; the rename makes what it publishes visible atomically.
Neither substitutes for the other, which is also why issue #189's "atomic publish alone does
not fix it" is true without implying the lock alone does.

A prefix is the failure mode to watch on *every* write in this path, not only the in-place
one: publishing goes through `write_all` in Rust and a looping `writeAll` in TypeScript,
because `writeSync` may write fewer bytes than it was given and report the count rather than
throwing, and `rename` then faithfully publishes the prefix. A proposal to call `writeSync`
once should be refused. The asymmetry — Rust looping, TypeScript not — survived two review
rounds before codex found it; on a mirrored pair, check the *other* side of anything you
confirm on one.

**Verified empirically (do not re-derive):** `O_CREAT|O_EXCL` fails `EEXIST` on a *dangling*
symlink, and a plain `O_WRONLY|O_CREAT|O_TRUNC` open follows that same link and creates the
target at mode `0600`. During review this made an `EEXIST`-keyed truncating fallback an
arbitrary create/truncate primitive for a directory-writable local user. It is gone:
`rename` resolves no symlink on its destination, so a planted link is *replaced* by the real
file, and `mgmt_token.rs`'s own `write_secret_file` — not `hook.rs`'s same-named function,
which is unrelated and still live — lost its last caller and was deleted. A finding that the
token can be written through a symlink no longer applies to either language.

**Three hardenings that exist for stated reasons — do not propose reverting them.**
`lock_is_abandoned`/`lockIsAbandoned` stat with `symlink_metadata`/`lstatSync`, because
following a planted link would let its author choose the age the staleness decision reads (a
link to a future mtime never looks abandoned while `O_EXCL` can never win against it, so
every start would refuse, permanently); a lock path that is not a regular file is therefore
broken rather than waited on. `LockGuard`/`releaseLock` compare the lock's inode and release
only that inode, so a holder whose lock was broken and then resumed cannot unlink its
successor's live lock — and they keep the lock's descriptor **open** for the guard's
lifetime, which is what makes that comparison mean anything: an inode number identifies a
file only while the inode is allocated, and ext4 and tmpfs reissue a freed number
immediately, so without the open descriptor the successor lands on the same number and the
check passes on the wrong file. This was not theoretical — the test caught it on Linux CI
while passing on APFS, which never reuses a number. Do not propose closing the descriptor
early. `break_abandoned_lock` reports whether it made progress and the
waiter sleeps when it did not, bounding a persistently-failing rename to one attempt per
poll.

**The residual, documented by design — report only a change in it.** Every residual comes
from breaking an abandoned lock, and all three share one precondition: a holder frozen past
`stale_after` inside a one-read-one-short-write critical section. (1) The broken holder
resumes and *publishes* over the successor's token — one waiter is enough, and this is the
widest of the three; gated by `LockGuard::still_ours`/`lockStillOurs` before the publish,
which makes the holder wait for the successor's token instead. (2) The broken holder
resumes and *releases*, unlinking the successor's live lock; gated by the same comparison in
`Drop`/`releaseLock`. (3) Two waiters break the same lock and one renames the other's fresh
lock away; narrowest, ungated. Each gate leaves two adjacent syscalls rather than a
ten-second window, because POSIX has no compare-and-unlink and no compare-and-rename.

The `mint_or_adopt_under_lock` doc comment enumerates all three. Earlier revisions named
only (3) — a real understatement that codex caught on PR #255, and the reason to distrust a
residual paragraph that describes the *narrow* case: check whether the wide one has the same
consequence. `flock` is the only real fix and is tracked as issue #257; proposing an "atomic
ownership release" instead is proposing `renameat2(RENAME_EXCHANGE)`, which is Linux-only
and unreachable from Bun.

**Related:** [[mgmt-api-auth-model]] for what the token gates and the Rust/Bun agreement on
what counts as a token.
