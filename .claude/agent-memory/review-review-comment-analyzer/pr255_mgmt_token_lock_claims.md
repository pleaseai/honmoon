---
name: pr255-mgmt-token-lock-claims
description: 'PR #255 (issue #189) doc-comment audit of the mgmt-token lock in mgmt_token.rs and auth.ts — all five claims were corrected before merge, and one of them was not merely inaccurate prose but the visible symptom of a real partial-read defect, which is the reusable lesson'
metadata:
  type: project
---

PR #255 added long, mirrored Rust/TS doc comments for a two-process single-winner
file-lock protocol (`mgmt-token.lock`). **Every claim below was corrected before the
PR merged** — this note records the patterns, not open findings. Do not re-report
them against the merged code.

1. **A false claim about a runtime API is checkable by running the runtime.**
   `sleepSync`'s doc said "the only synchronous sleep the runtime offers" while
   `Bun.sleepSync(ms)` exists, verified by running `bun -e "Bun.sleepSync(1)"` in the
   repo's own toolchain. An absolute claim about a *runtime API surface* is worth
   testing by invoking the candidate, not by reasoning from memory about what Node
   and Bun expose. (Merged code now calls `Bun.sleepSync`; this package is already a
   Bun service via `Bun.serve`/`Bun.file`.)

2. **A self-contradicting absolute inside one doc comment.** The comment said "A
   waiter never mints, which is what makes this single-winner" and then, in its own
   "what the lock does not cover" section, described two *waiters* where "Both would
   mint." Flag the absolute sentence itself, not only the exception paragraph — a
   reader who stops at the first sentence keeps the false version. Merged wording
   qualifies it to the live-lock case it actually holds for. See
   [[guard-unnecessary-doc-comment]] for the sibling pattern.

3. **The most valuable finding of the round, and the reason to take this class
   seriously: a false mechanism claim was the visible end of a real bug.** The
   comment said "no other start reads the file until the lock is released," which
   the code below it contradicts — the lost-the-lock branch reads immediately, with
   no wait. The review's first pass concluded the code was nonetheless safe because
   "a mid-write empty/partial read just causes another poll, not a mint." **That
   conclusion was wrong.** A partial read is a *non-empty* string, so it resolves as
   a token and is adopted: the PR's own race test then caught a start holding a
   63-character token against a 64-character file. The fix was not to reword the
   comment but to make the publish atomic (write-to-staging then `rename`) — see
   [[mgmt-token-lock-protocol]]. Lesson: when a comment's stated mechanism is false,
   do not stop at substituting a narrower mechanism you believe is true; check that
   the substitute actually holds, because the false claim is often covering for the
   defect rather than merely mis-describing the defence. This is the #150
   "documented contract the code does not keep" pattern with a bug behind it.

4. **Stale intra-doc links, not prose.** Two `[`recover_empty_token_file`]` rustdoc
   links named a function renamed to `mint_or_adopt_under_lock` mid-PR. Grep every
   backtick-bracket rustdoc and `{@link}` target named in new comments; a rename that
   touches doc links is an easy miss, and `cargo doc` is not run with `-D warnings`
   in CI so nothing else catches it.

5. **A quantifier with no stated basis.** "About five orders of magnitude of
   headroom" compared 10s to an unstated critical-section cost (µs-level I/O gives
   1e5, ms-level 1e4). Merged text states the basis and gives the range. Consistent
   with [[hook_rs_salt_exposure_pr170]] and
   [[docs-completeness-claim-unbounded-review]].

6. **A comment on a *test* is a contract too, and a false one hides a test that
   proves nothing.** `a_failed_publish_still_releases_the_lock` and its TS twin
   said "the lock is taken while the directory is still writable, and the publish
   then fails on the staging create" — but the `0500` chmod came *before* the
   resolver ran, so `acquire_lock`'s own exclusive create failed first and the
   publish was never reached. The lock was therefore never created, and the
   assertion `!lock_path.exists()` passed on its absence rather than on its
   release: stubbing `Drop` out left the test green. Both were restructured to
   leave the directory writable and put a directory where the staging file has to
   be created, and re-checked by stubbing the release out (red) and restoring it
   (green). Read a test's setup against the order the production code runs its
   steps in; a comment describing an ordering the setup does not produce is the
   same #150 pattern as a false doc contract, with a vacuous test behind it
   instead of a bug.

Claims that held on cross-checking: lock file name, directory and protocol identical
across Rust and TS; `break_abandoned_lock`'s rename-makes-removal-a-claim argument;
the wiki flag-table numbers matching `LockTiming::DEFAULT` / `DEFAULT_LOCK_TIMING`.
