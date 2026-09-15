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

**Verified empirically (do not re-derive):** `O_CREAT|O_EXCL` fails `EEXIST` on a *dangling*
symlink, and a plain `O_WRONLY|O_CREAT|O_TRUNC` open follows that same link and creates the
target at mode `0600`. During review this made an `EEXIST`-keyed truncating fallback an
arbitrary create/truncate primitive for a directory-writable local user. It is gone:
`rename` resolves no symlink on its destination, so a planted link is *replaced* by the real
file, and `write_secret_file` has no callers left and was deleted. A finding that the token
can be written through a symlink no longer applies to either language.

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

**The residual, documented by design — report only a change in it:** a waiter observes an
abandoned lock and, between its staleness check and its rename, another waiter breaks the
same lock and takes a fresh one that the first then renames away; both would mint. The
release side carries the same window under the same precondition — it checks the inode and
then unlinks, and POSIX has no compare-and-unlink — which is one residual seen from two
ends, not two. Both ends are stated in the `mint_or_adopt_under_lock` doc comment along
with the reason `flock` is not used (Bun does not expose it, so the two runtimes could not
spell the same protocol). Proposing an "atomic ownership release" here is proposing
`renameat2(RENAME_EXCHANGE)`, which is Linux-only and unreachable from Bun.

**Related:** [[mgmt-api-auth-model]] for what the token gates and the Rust/Bun agreement on
what counts as a token.
